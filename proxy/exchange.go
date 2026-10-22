package proxy

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
	"gonum.org/v1/gonum/stat/sampleuv"
)

// exchangeUpstreams resolves req using the given upstreams.  It returns the DNS
// response, the upstream that successfully resolved the request, and the error
// if any.
func (p *Proxy) exchangeUpstreams(
	ctx context.Context,
	req *dns.Msg,
	ups []upstream.Upstream,
) (resp *dns.Msg, u upstream.Upstream, err error) {
	switch p.upstreamMode {
	case UpstreamModeParallel:
		return upstream.ExchangeParallel(ctx, ups, req)
	case UpstreamModeFastestAddr:
		switch req.Question[0].Qtype {
		case dns.TypeA, dns.TypeAAAA:
			return p.fastestAddr.ExchangeFastest(ctx, req, ups)
		default:
			// Go on to the load-balancing mode.
		}
	default:
		// Go on to the load-balancing mode.
	}

	if len(ups) == 1 {
		u = ups[0]
		resp, _, err = p.exchange(ctx, u, req)
		if err != nil {
			return nil, nil, err
		}

		// TODO(e.burkov):  Consider updating the RTT of a single upstream.

		return resp, u, err
	}

	w := sampleuv.NewWeighted(p.calcWeights(ups), p.randSrc)
	var errs []error
	for i, ok := w.Take(); ok; i, ok = w.Take() {
		u = ups[i]

		var elapsed time.Duration
		resp, elapsed, err = p.exchange(ctx, u, req)
		if err == nil {
			p.updateRTT(u.Address(), elapsed)

			return resp, u, nil
		}

		errs = append(errs, err)

		p.updateRTT(u.Address(), p.upstreamTimeout)
	}

	err = fmt.Errorf("all upstreams failed to exchange request: %w", errors.Join(errs...))

	return nil, nil, err
}

// exchange returns the result of the DNS request exchange with the given
// upstream and the elapsed time.  u and req must not be nil.
func (p *Proxy) exchange(
	ctx context.Context,
	u upstream.Upstream,
	req *dns.Msg,
) (resp *dns.Msg, dur time.Duration, err error) {
	startTime := p.time.Now()
	resp, err = u.Exchange(ctx, req)

	// Don't use [time.Since] because it uses [time.Now].
	dur = p.time.Now().Sub(startTime)

	addr := u.Address()
	q := &req.Question[0]
	if err != nil {
		p.logger.ErrorContext(
			ctx,
			"exchange failed",
			"upstream", addr,
			"question", q,
			"duration", dur,
			slogutil.KeyError, err,
		)
	} else {
		p.logger.DebugContext(
			ctx,
			"exchange successfully finished",
			"upstream", addr,
			"question", q,
			"duration", dur,
		)
	}

	return resp, dur, err
}

// upstreamRTTStats is the statistics for a single upstream's round-trip time.
type upstreamRTTStats struct {
	// last is the time of the latest update.  It's zero if there were no
	// updates.
	last time.Time

	// ewma is the exponentially weighted moving average of the round-trip
	// time in microseconds.
	ewma float64
}

// update returns updated stats after adding given RTT measured at now.  Older
// samples' weight decays by a factor of e per tau.  tau must be positive.
func (stats upstreamRTTStats) update(
	rtt time.Duration,
	now time.Time,
	tau time.Duration,
) (updated upstreamRTTStats) {
	sample := float64(rtt.Microseconds())
	if stats.last.IsZero() {
		return upstreamRTTStats{
			last: now,
			ewma: sample,
		}
	}

	// Clamp to keep the weight within [0, 1] if the clock goes backwards.
	elapsed := max(now.Sub(stats.last), 0)
	w := math.Exp(-elapsed.Seconds() / tau.Seconds())

	return upstreamRTTStats{
		last: now,
		ewma: w*stats.ewma + (1-w)*sample,
	}
}

// calcWeights returns the slice of weights, each corresponding to the upstream
// with the same index in the given slice.  ups elements must not be nil.
func (p *Proxy) calcWeights(ups []upstream.Upstream) (weights []float64) {
	weights = make([]float64, 0, len(ups))

	p.rttLock.Lock()
	defer p.rttLock.Unlock()

	for _, u := range ups {
		stat := p.upstreamRTTStats[u.Address()]
		if stat.ewma == 0 {
			// Use 1 as the default weight.
			weights = append(weights, 1)
		} else {
			weights = append(weights, 1/stat.ewma)
		}
	}

	return weights
}

// updateRTT updates the round-trip time in [upstreamRTTStats] for given
// address.
func (p *Proxy) updateRTT(address string, rtt time.Duration) {
	now := p.time.Now()

	p.rttLock.Lock()
	defer p.rttLock.Unlock()

	if p.upstreamRTTStats == nil {
		p.upstreamRTTStats = map[string]upstreamRTTStats{}
	}

	p.upstreamRTTStats[address] = p.upstreamRTTStats[address].update(rtt, now, p.upstreamRTTDecay)
}
