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
		name     string
		servers  []upstream.Upstream
	}{{
		wantStat: map[string]int64{
			fastUps.Address():    8910,
			slowerUps.Address():  902,
			slowestUps.Address(): 188,
		},
		name:    "all_good",
		servers: []upstream.Upstream{slowestUps, slowerUps, fastUps},
	}, {
		wantStat: map[string]int64{
			fastUps.Address():   9110,
			slowerUps.Address(): 890,
			err1Ups.Address():   6,
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
			fastUps.Address():    3542,
			slowerUps.Address():  375,
			fastestUps.Address(): 6084,
		},
		name:    "error_once",
		servers: []upstream.Upstream{fastUps, slowerUps, fastestUps},
	}, {
		wantStat: map[string]int64{
			each200.Address(): 5192,
			each100.Address(): 3100,
			each50.Address():  1800,
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

		wantStat := tc.wantStat

		t.Run(tc.name, func(t *testing.T) {
			for range requestsNum {
				ctx := testutil.ContextWithTimeout(t, defaultTimeout)

				_ = p.Resolve(ctx, &DNSContext{Req: req, Addr: cli})
				currentNow = currentNow.Add(reqInterval)
			}

			assert.Equal(t, wantStat, stats)
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

	start := time.Unix(0, 0)
	prev := upstreamRTTStats{}.update(prevRTT, start, tau)

	prevUS := float64(prevRTT.Microseconds())
	newUS := float64(newRTT.Microseconds())

	testCases := []struct {
		now      time.Time
		name     string
		wantEWMA float64
	}{{
		now:      start,
		name:     "no_time_passed",
		wantEWMA: prevUS,
	}, {
		now:      start.Add(-time.Second),
		name:     "clock_backwards",
		wantEWMA: prevUS,
	}, {
		now:      start.Add(tau),
		name:     "one_tau",
		wantEWMA: newUS + (prevUS-newUS)/math.E,
	}, {
		now:      start.Add(100 * tau),
		name:     "long_ago",
		wantEWMA: newUS,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := prev.update(newRTT, tc.now, tau)
			assert.InDelta(t, tc.wantEWMA, got.ewma, 1e-6)
			assert.Equal(t, tc.now, got.last)
		})
	}

	t.Run("first_sample", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, prevUS, prev.ewma)
		assert.Equal(t, start, prev.last)
	})
}

func TestProxy_exchangeUpstreams_failurePenalty(t *testing.T) {
	t.Parallel()

	const upsTimeout = 3 * time.Second

	okUps := &testUpstream{
		OnExchange: func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
			return (&dns.Msg{}).SetReply(req), nil
		},
		OnAddress: func() (addr string) { return "ok" },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
	}
	errUps := &testUpstream{
		OnExchange: func(_ context.Context, _ *dns.Msg) (r *dns.Msg, err error) {
			return nil, assert.AnError
		},
		OnAddress: func() (addr string) { return "error" },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
	}

	ups := []upstream.Upstream{okUps, errUps}
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

	// Without samples both upstreams have the same weight, so the erroring one
	// is tried within a few requests.
	req := dnsproxytest.NewTestRequest()
	for range 100 {
		ctx := testutil.ContextWithTimeout(t, defaultTimeout)
		_, _, err := p.exchangeUpstreams(ctx, req, ups)
		if !assert.NoError(t, err) {
			return
		}

		p.rttLock.Lock()
		stat, ok := p.upstreamRTTStats[errUps.Address()]
		p.rttLock.Unlock()

		if ok {
			assert.Equal(t, float64(upsTimeout.Microseconds()), stat.ewma)

			return
		}
	}

	t.Fatal("erroring upstream was never tried")
}

// burstUpstream is an [upstream.Upstream] with a constant RTT that fails
// failNum consecutive exchanges starting with the failStart-th one, counting
// from 1.  It isn't safe for concurrent use.
type burstUpstream struct {
	// now is the fake current time, advanced by the exchange duration.
	now *time.Time

	// firstFail is the time of the first failed exchange.
	firstFail time.Time

	// recovered is the time of the first successful exchange after the
	// failures.
	recovered time.Time

	name      string
	rtt       time.Duration
	timeout   time.Duration
	failStart uint
	failNum   uint
	n         uint
}

// type check
var _ upstream.Upstream = (*burstUpstream)(nil)

// Exchange implements the [upstream.Upstream] interface for *burstUpstream.
func (u *burstUpstream) Exchange(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
	u.n++
	if u.n >= u.failStart && u.n < u.failStart+u.failNum {
		if u.firstFail.IsZero() {
			u.firstFail = *u.now
		}

		*u.now = u.now.Add(u.timeout)

		return nil, assert.AnError
	}

	if u.n == u.failStart+u.failNum {
		u.recovered = *u.now
	}

	*u.now = u.now.Add(u.rtt)

	return (&dns.Msg{}).SetReply(req), nil
}

// Address implements the [upstream.Upstream] interface for *burstUpstream.
func (u *burstUpstream) Address() (addr string) { return u.name }

// Close implements the [upstream.Upstream] interface for *burstUpstream.
func (u *burstUpstream) Close() (err error) { panic(testutil.UnexpectedCall()) }

// loadBalanceBurstResult is the result of [runLoadBalanceBurst].
type loadBalanceBurstResult struct {
	// stats are the numbers of exchanges per upstream address.
	stats map[string]int64

	// burst is the upstream that fails its exchanges.
	burst *burstUpstream

	// burstRTT is the final statistics of burst.
	burstRTT upstreamRTTStats
}

// runLoadBalanceBurst resolves requestsNum requests, one per reqInterval, over
// upstreams with RTTs of 5, 10, and 100 ms.  The 5 ms one fails failNum
// consecutive exchanges starting with its failStart-th.  The proxy uses the
// default RTT decay and upstream timeout.
func runLoadBalanceBurst(
	t *testing.T,
	seed uint64,
	requestsNum int,
	reqInterval time.Duration,
	failStart uint,
	failNum uint,
) (res *loadBalanceBurstResult) {
	t.Helper()

	currentNow := time.Unix(0, 0)
	clock := &faketime.Clock{
		OnNow: func() (now time.Time) {
			now, currentNow = currentNow, currentNow.Add(time.Microsecond)

			return now
		},
	}

	newUps := func(name string, rtt time.Duration) (u *burstUpstream) {
		return &burstUpstream{
			now:     &currentNow,
			name:    name,
			rtt:     rtt,
			timeout: defaultTimeout,
		}
	}

	burst := newUps("burst", 5*time.Millisecond)
	burst.failStart, burst.failNum = failStart, failNum

	stats := map[string]int64{}
	ups := []upstream.Upstream{}
	for _, u := range []*burstUpstream{
		burst,
		newUps("fast", 10*time.Millisecond),
		newUps("slower", 100*time.Millisecond),
	} {
		ups = append(ups, measuredUpstream{Upstream: u, stats: stats})
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
	p.randSrc = rand.New(rand.NewPCG(seed, seed))

	req := dnsproxytest.NewTestRequest()
	for range requestsNum {
		ctx := testutil.ContextWithTimeout(t, defaultTimeout)
		_, _, err := p.exchangeUpstreams(ctx, req, ups)
		require.NoError(t, err)

		currentNow = currentNow.Add(reqInterval)
	}

	return &loadBalanceBurstResult{
		stats:    stats,
		burst:    burst,
		burstRTT: p.upstreamRTTStats[burst.name],
	}
}

func TestProxy_Exchange_loadBalanceBurst(t *testing.T) {
	t.Parallel()

	const (
		// reqInterval is 300 requests per hour.
		reqInterval = 12 * time.Second
		requestsNum = 30_000
		seed        = 42
		failStart   = 1000
		failNum     = 10
	)

	base := runLoadBalanceBurst(t, seed, requestsNum, reqInterval, failStart, 0)
	got := runLoadBalanceBurst(t, seed, requestsNum, reqInterval, failStart, failNum)

	assert.Equal(t, map[string]int64{
		"burst":  19_382,
		"fast":   9_623,
		"slower": 995,
	}, base.stats)
	assert.Equal(t, map[string]int64{
		"burst":  12_921,
		"fast":   15_522,
		"slower": 1_567,
	}, got.stats)

	burst := got.burst
	require.False(t, burst.recovered.IsZero(), "burst upstream never recovered")

	// By the end of the run the estimate has returned to the upstream's RTT.
	assert.InEpsilon(t, float64(burst.rtt.Microseconds()), got.burstRTT.ewma, 1e-3)

	t.Logf(
		"lost picks: %d; failures to recovery: %s",
		base.stats[burst.name]-got.stats[burst.name],
		burst.recovered.Sub(burst.firstFail),
	)
}
