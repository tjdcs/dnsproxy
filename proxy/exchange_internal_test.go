package proxy

import (
	"context"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/faketime"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newUpstreamWithErrorRate returns an [upstream.Upstream] that responds with an
// error every [rate] requests.  The returned upstream isn't safe for concurrent
// use.
func newUpstreamWithErrorRate(rate uint, name string) (u upstream.Upstream) {
	var n uint

	return &testUpstream{
		OnExchange: func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
			n++
			if n%rate == 0 {
				return nil, assert.AnError
			}

			return (&dns.Msg{}).SetReply(req), nil
		},
		OnAddress: func() (addr string) { return name },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
	}
}

// measuredUpstream is an [upstream.Upstream] that increments the counter every
// time it's used.
type measuredUpstream struct {
	// Upstream is embedded here to avoid implementing all the methods.
	upstream.Upstream

	// stats is the statistics collector for current upstream.
	stats map[string]int64
}

// type check
var _ upstream.Upstream = measuredUpstream{}

// Exchange implements the [upstream.Upstream] interface for measuredUpstream.
func (u measuredUpstream) Exchange(ctx context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
	u.stats[u.Address()]++

	return u.Upstream.Exchange(ctx, req)
}

func TestProxy_Exchange_loadBalance(t *testing.T) {
	// Make the test deterministic.
	randSrc := rand.New(rand.NewPCG(42, 42))

	const (
		testRTT     = 1 * time.Second
		requestsNum = 10_000

		// reqInterval is the time between requests.  requestsNum requests
		// span many [DefaultUpstreamRTTDecay] periods.
		reqInterval = DefaultUpstreamRTTDecay / 100
	)

	// clock returns the value of currentNow and advances it by a microsecond.
	// Upstreams advance currentNow by their RTT.
	currentNow := time.Unix(0, 0)
	clock := &faketime.Clock{
		OnNow: func() (now time.Time) {
			now, currentNow = currentNow, currentNow.Add(time.Microsecond)

			return now
		},
	}

	fastUps := &testUpstream{
		OnExchange: func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
			currentNow = currentNow.Add(testRTT / 100)

			return (&dns.Msg{}).SetReply(req), nil
		},
		OnAddress: func() (addr string) { return "fast" },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
	}
	slowerUps := &testUpstream{
		OnExchange: func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
			currentNow = currentNow.Add(testRTT / 10)

			return (&dns.Msg{}).SetReply(req), nil
		},
		OnAddress: func() (addr string) { return "slower" },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
	}
	slowestUps := &testUpstream{
		OnExchange: func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
			currentNow = currentNow.Add(testRTT / 2)

			return (&dns.Msg{}).SetReply(req), nil
		},
		OnAddress: func() (addr string) { return "slowest" },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
	}

	err1Ups := &testUpstream{
		OnExchange: func(_ context.Context, _ *dns.Msg) (r *dns.Msg, err error) {
			return nil, assert.AnError
		},
		OnAddress: func() (addr string) { return "error1" },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
	}
	err2Ups := &testUpstream{
		OnExchange: func(_ context.Context, _ *dns.Msg) (r *dns.Msg, err error) {
			return nil, assert.AnError
		},
		OnAddress: func() (addr string) { return "error2" },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
	}

	singleError := &sync.Once{}
	// fastestUps responds with an error on the first request.
	fastestUps := &testUpstream{
		OnExchange: func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
			singleError.Do(func() { err = assert.AnError })
			currentNow = currentNow.Add(testRTT / 200)

			return (&dns.Msg{}).SetReply(req), err
		},
		OnAddress: func() (addr string) { return "fastest" },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
	}

	each200 := newUpstreamWithErrorRate(200, "each_200")
	each100 := newUpstreamWithErrorRate(100, "each_100")
	each50 := newUpstreamWithErrorRate(50, "each_50")

	testCases := []struct {
		wantStat map[string]int64
		// wantRTT, if not nil, are the expected RTT estimates at the end.
		wantRTT map[string]time.Duration
		name    string
		servers []upstream.Upstream
	}{{
		wantStat: map[string]int64{
			// Shares go as RTT^-3: 10x slower gets about 1/1000.
			fastUps.Address():    9983,
			slowerUps.Address():  12,
			slowestUps.Address(): 5,
		},
		wantRTT: map[string]time.Duration{
			fastUps.Address():    testRTT / 100,
			slowerUps.Address():  testRTT / 10,
			slowestUps.Address(): testRTT / 2,
		},
		name:    "all_good",
		servers: []upstream.Upstream{slowestUps, slowerUps, fastUps},
	}, {
		wantStat: map[string]int64{
			fastUps.Address():   9984,
			slowerUps.Address(): 16,
			// Never answered, so no baseline: its weight is pulled
			// towards 1/3 between failures, slower after each one.
			err1Ups.Address(): 25,
		},
		name:    "one_bad",
		servers: []upstream.Upstream{fastUps, err1Ups, slowerUps},
	}, {
		wantStat: map[string]int64{
			err1Ups.Address(): requestsNum,
			err2Ups.Address(): requestsNum,
		},
		name:    "all_bad",
		servers: []upstream.Upstream{err2Ups, err1Ups},
	}, {
		wantStat: map[string]int64{
			fastUps.Address():    1759,
			slowerUps.Address():  10,
			fastestUps.Address(): 8232,
		},
		// The single failure has decayed away.
		wantRTT: map[string]time.Duration{
			fastUps.Address():    testRTT / 100,
			slowerUps.Address():  testRTT / 10,
			fastestUps.Address(): testRTT / 200,
		},
		name:    "error_once",
		servers: []upstream.Upstream{fastUps, slowerUps, fastestUps},
	}, {
		wantStat: map[string]int64{
			each200.Address(): 5600,
			each100.Address(): 2861,
			each50.Address():  1627,
		},
		name:    "error_each_nth",
		servers: []upstream.Upstream{each200, each100, each50},
	}}

	req := dnsproxytest.NewTestRequest()
	cli := netip.AddrPortFrom(netutil.IPv4Localhost(), 1234)

	for _, tc := range testCases {
		ups := []upstream.Upstream{}
		stats := map[string]int64{}
		for _, s := range tc.servers {
			ups = append(ups, measuredUpstream{
				Upstream: s,
				stats:    stats,
			})
		}

		p := mustNew(t, &Config{
			Logger:        testLogger,
			UDPListenAddr: []*net.UDPAddr{dnsproxytest.LocalhostAnyPortUDP},
			TCPListenAddr: []*net.TCPAddr{dnsproxytest.LocalhostAnyPortTCP},
			UpstreamConfig: &UpstreamConfig{
				Upstreams: ups,
			},
			TrustedProxies: dnsproxytest.DefaultTrustedProxies,
		})
		p.time = clock
		p.randSrc = randSrc

		wantStat, wantRTT := tc.wantStat, tc.wantRTT

		t.Run(tc.name, func(t *testing.T) {
			for range requestsNum {
				ctx := testutil.ContextWithTimeout(t, defaultTimeout)

				_ = p.Resolve(ctx, &DNSContext{Req: req, Addr: cli})
				currentNow = currentNow.Add(reqInterval)
			}

			assert.Equal(t, wantStat, stats)

			for addr, rtt := range wantRTT {
				got := p.upstreamRTTStats[addr].ewma
				assert.InEpsilon(t, float64(rtt.Microseconds()), got, 1e-3, addr)
			}
		})
	}
}

func TestUpstreamRTTStats_update(t *testing.T) {
	t.Parallel()

	const (
		tau     = 10 * time.Second
		prevRTT = 100 * time.Millisecond
		newRTT  = 10 * time.Millisecond
	)

	prevUS := float64(prevRTT.Microseconds())
	newUS := float64(newRTT.Microseconds())

	start := time.Unix(0, 0)
	prev := upstreamRTTStats{
		last: start,
		ewma: prevUS,
	}

	testCases := []struct {
		now      time.Time
		name     string
		stats    upstreamRTTStats
		wantEWMA float64
	}{{
		now:      start,
		stats:    upstreamRTTStats{},
		name:     "first_sample",
		wantEWMA: newUS,
	}, {
		now:      start,
		stats:    prev,
		name:     "no_time_passed",
		wantEWMA: prevUS,
	}, {
		now:      start.Add(-time.Second),
		stats:    prev,
		name:     "clock_backwards",
		wantEWMA: prevUS,
	}, {
		now:      start.Add(tau),
		stats:    prev,
		name:     "one_tau",
		wantEWMA: newUS + (prevUS-newUS)/math.E,
	}, {
		now:      start.Add(100 * tau),
		stats:    prev,
		name:     "long_ago",
		wantEWMA: newUS,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := tc.stats.update(newRTT, tc.now, tau)
			assert.InDelta(t, tc.wantEWMA, got.ewma, 1e-6)
			assert.Equal(t, tc.now, got.last)
		})
	}
}

func TestProxy_exchangeUpstreams_failurePenalty(t *testing.T) {
	t.Parallel()

	const upsTimeout = 3 * time.Second

	newErrUps := func(addr string) (u upstream.Upstream) {
		return &testUpstream{
			OnExchange: func(_ context.Context, _ *dns.Msg) (r *dns.Msg, err error) {
				return nil, assert.AnError
			},
			OnAddress: func() (a string) { return addr },
			OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
		}
	}

	ups := []upstream.Upstream{newErrUps("error1"), newErrUps("error2")}
	p := mustNew(t, &Config{
		Logger:        testLogger,
		UDPListenAddr: []*net.UDPAddr{dnsproxytest.LocalhostAnyPortUDP},
		TCPListenAddr: []*net.TCPAddr{dnsproxytest.LocalhostAnyPortTCP},
		UpstreamConfig: &UpstreamConfig{
			Upstreams: ups,
		},
		TrustedProxies:  dnsproxytest.DefaultTrustedProxies,
		UpstreamTimeout: upsTimeout,
	})

	// Both upstreams fail, so both are tried and penalized.
	ctx := testutil.ContextWithTimeout(t, defaultTimeout)
	_, _, err := p.exchangeUpstreams(ctx, dnsproxytest.NewTestRequest(), ups)
	require.Error(t, err)

	for _, u := range ups {
		assert.Equal(t, float64(upsTimeout.Microseconds()), p.upstreamRTTStats[u.Address()].ewma)
	}
}

func TestUpstreamRTTStats_updateBase(t *testing.T) {
	t.Parallel()

	const (
		tau     = 10 * time.Second
		prevRTT = 100 * time.Millisecond
		newRTT  = 10 * time.Millisecond
	)

	prevUS := float64(prevRTT.Microseconds())
	newUS := float64(newRTT.Microseconds())

	start := time.Unix(0, 0)
	warmingUp := upstreamRTTStats{
		baseLast: start,
		base:     prevUS,
		baseNum:  1,
		baseMax:  prevUS,
	}
	// lastWarmUp holds a slow first answer and three fast ones.
	lastWarmUp := upstreamRTTStats{
		baseLast: start,
		base:     (5*prevUS + 3*newUS) / 4,
		baseNum:  upstreamRTTBaselineMin - 1,
		baseMax:  5 * prevUS,
	}
	warmedUp := upstreamRTTStats{
		baseLast: start,
		base:     prevUS,
		baseNum:  upstreamRTTBaselineMin,
	}
	warm := upstreamRTTStats{
		baseLast: start,
		base:     prevUS,
		baseNum:  1e6,
	}

	testCases := []struct {
		now      time.Time
		name     string
		stats    upstreamRTTStats
		wantBase float64
	}{{
		now:      start,
		stats:    upstreamRTTStats{},
		name:     "first_sample",
		wantBase: newUS,
	}, {
		now:      start,
		stats:    warmingUp,
		name:     "warm_up_averages",
		wantBase: (prevUS + newUS) / 2,
	}, {
		now:      start.Add(tau),
		stats:    warmingUp,
		name:     "warm_up_ignores_decay",
		wantBase: (prevUS + newUS) / 2,
	}, {
		now:      start.Add(tau),
		stats:    lastWarmUp,
		name:     "warm_up_drops_largest",
		wantBase: newUS,
	}, {
		now:      start.Add(tau),
		stats:    warmedUp,
		name:     "warmed_up_decay_wins",
		wantBase: newUS + (prevUS-newUS)/math.E,
	}, {
		now:      start,
		stats:    warm,
		name:     "warm_no_time_passed",
		wantBase: prevUS + (newUS-prevUS)/(warm.baseNum+1),
	}, {
		now:      start.Add(tau),
		stats:    warm,
		name:     "warm_one_tau",
		wantBase: newUS + (prevUS-newUS)/math.E,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := tc.stats.updateBase(newRTT, tc.now, tau)
			assert.InDelta(t, tc.wantBase, got.base, 1e-6)
			assert.Equal(t, tc.now, got.baseLast)
			assert.Equal(t, tc.stats.baseNum+1, got.baseNum)
		})
	}
}

func TestUpstreamRTTStats_estimate(t *testing.T) {
	t.Parallel()

	const (
		tau  = 10 * time.Second
		ewma = 5_000_000.0
		base = 10_000.0
	)

	start := time.Unix(0, 0)
	stats := upstreamRTTStats{
		last:    start,
		ewma:    ewma,
		base:    base,
		baseNum: upstreamRTTBaselineMin,
	}

	testCases := []struct {
		now   time.Time
		name  string
		stats upstreamRTTStats
		want  float64
	}{{
		now:   start.Add(100 * tau),
		stats: upstreamRTTStats{last: start, ewma: ewma},
		name:  "no_baseline",
		want:  ewma,
	}, {
		now:   start.Add(100 * tau),
		stats: upstreamRTTStats{last: start, ewma: ewma, base: base, baseNum: upstreamRTTBaselineMin - 1},
		name:  "warming_up",
		want:  ewma,
	}, {
		now:   start,
		stats: stats,
		name:  "fresh",
		want:  ewma,
	}, {
		now:   start.Add(-time.Second),
		stats: stats,
		name:  "clock_backwards",
		want:  ewma,
	}, {
		now:   start.Add(tau),
		stats: stats,
		name:  "one_tau",
		want:  base + (ewma-base)/math.E,
	}, {
		now:   start.Add(100 * tau),
		stats: stats,
		name:  "stale",
		want:  base,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.InDelta(t, tc.want, tc.stats.estimate(tc.now, tau), 1e-6)
		})
	}
}

func TestProxy_calcWeights(t *testing.T) {
	t.Parallel()

	newUps := func(addr string) (u upstream.Upstream) {
		return &testUpstream{
			OnAddress: func() (a string) { return addr },
		}
	}

	ups := []upstream.Upstream{newUps("fast"), newUps("slow"), newUps("unmeasured")}

	p := mustNew(t, &Config{
		Logger:        testLogger,
		UDPListenAddr: []*net.UDPAddr{dnsproxytest.LocalhostAnyPortUDP},
		TCPListenAddr: []*net.TCPAddr{dnsproxytest.LocalhostAnyPortTCP},
		UpstreamConfig: &UpstreamConfig{
			Upstreams: ups,
		},
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
	})
	now := time.Unix(1_000_000, 0)
	p.time = &faketime.Clock{
		OnNow: func() (n time.Time) { return now },
	}

	ctx := testutil.ContextWithTimeout(t, defaultTimeout)

	t.Run("exponent", func(t *testing.T) {
		p.upstreamRTTStats["fast"] = upstreamRTTStats{last: now, ewma: 1_000, base: 1_000, baseNum: upstreamRTTBaselineMin}
		p.upstreamRTTStats["slow"] = upstreamRTTStats{last: now, ewma: 2_000, base: 2_000, baseNum: upstreamRTTBaselineMin}

		w := p.calcWeights(ctx, ups)
		require.Len(t, w, len(ups))

		// Twice as slow gets an eighth of the weight, and an unmeasured
		// upstream is tried first.
		assert.InDelta(t, 8, w[0]/w[1], 1e-9)
		assert.Greater(t, w[2], 0.99)
	})

	// failed is an upstream whose only exchange failed, so it has no
	// baseline.
	failed := upstreamRTTStats{ewma: float64(defaultTimeout.Microseconds())}
	measured := []upstream.Upstream{ups[0], ups[1]}
	p.upstreamRTTStats["fast"] = upstreamRTTStats{last: now, ewma: 1_000, base: 1_000, baseNum: upstreamRTTBaselineMin}

	t.Run("no_baseline_fresh", func(t *testing.T) {
		failed.last = now
		p.upstreamRTTStats["slow"] = failed

		w := p.calcWeights(ctx, measured)
		assert.Less(t, w[1], 1e-6)
	})

	t.Run("no_baseline_stale", func(t *testing.T) {
		failed.last = now.Add(-100 * p.upstreamRTTDecay)
		p.upstreamRTTStats["slow"] = failed

		w := p.calcWeights(ctx, measured)
		assert.InDelta(t, 0.5, w[1], 1e-6)
	})

	t.Run("slow_first_answer_stale", func(t *testing.T) {
		// A single slow answer doesn't exclude the upstream: until its
		// baseline is complete, it's pulled towards 1/2 like the above.
		p.upstreamRTTStats["slow"] = upstreamRTTStats{
			last:     now.Add(-100 * p.upstreamRTTDecay),
			ewma:     500_000,
			baseLast: now.Add(-100 * p.upstreamRTTDecay),
			base:     500_000,
			baseNum:  1,
			baseMax:  500_000,
		}

		w := p.calcWeights(ctx, measured)
		assert.InDelta(t, 0.5, w[1], 1e-6)
	})
}

func TestProxy_updateRTT_baseline(t *testing.T) {
	t.Parallel()

	const (
		addr = "upstream"
		rtt  = 10 * time.Millisecond
	)

	p := mustNew(t, &Config{
		Logger:        testLogger,
		UDPListenAddr: []*net.UDPAddr{dnsproxytest.LocalhostAnyPortUDP},
		TCPListenAddr: []*net.TCPAddr{dnsproxytest.LocalhostAnyPortTCP},
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{&testUpstream{
				OnAddress: func() (a string) { return addr },
			}},
		},
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
	})

	ctx := testutil.ContextWithTimeout(t, defaultTimeout)

	// A failure updates the moving average but not the baseline.
	p.updateRTT(ctx, addr, p.upstreamTimeout, false)
	stat := p.upstreamRTTStats[addr]
	assert.Equal(t, float64(p.upstreamTimeout.Microseconds()), stat.ewma)
	assert.Zero(t, stat.base)
	assert.Zero(t, stat.baseNum)

	assert.Equal(t, uint(1), stat.fails)

	p.updateRTT(ctx, addr, p.upstreamTimeout, false)
	assert.Equal(t, uint(2), p.upstreamRTTStats[addr].fails)

	p.updateRTT(ctx, addr, rtt, true)
	stat = p.upstreamRTTStats[addr]
	assert.Equal(t, float64(rtt.Microseconds()), stat.base)
	assert.Equal(t, 1.0, stat.baseNum)
	assert.Zero(t, stat.fails)
}

func TestUpstreamRTTStats_pullDecay(t *testing.T) {
	t.Parallel()

	const tau = 5 * time.Minute

	testCases := []struct {
		name  string
		fails uint
		want  time.Duration
	}{{
		name:  "healthy",
		fails: 0,
		want:  tau,
	}, {
		name:  "one_failure",
		fails: 1,
		want:  tau,
	}, {
		name:  "two_failures",
		fails: 2,
		want:  2 * tau,
	}, {
		name:  "four_failures",
		fails: 4,
		want:  8 * tau,
	}, {
		name:  "capped",
		fails: 1_000,
		want:  upstreamRTTMaxPullDecay,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stats := upstreamRTTStats{fails: tc.fails}
			assert.Equal(t, tc.want, stats.pullDecay(tau))
		})
	}

	t.Run("tau_above_cap", func(t *testing.T) {
		t.Parallel()

		stats := upstreamRTTStats{fails: 3}
		assert.Equal(t, 2*upstreamRTTMaxPullDecay, stats.pullDecay(2*upstreamRTTMaxPullDecay))
	})
}
