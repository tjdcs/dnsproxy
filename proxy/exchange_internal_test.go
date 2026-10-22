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
			fastUps.Address():    8910,
			slowerUps.Address():  902,
			slowestUps.Address(): 188,
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
		stats    upstreamRTTStats
		name     string
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
