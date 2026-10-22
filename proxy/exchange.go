package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
	"gonum.org/v1/gonum/stat/sampleuv"
)

const (
	// upstreamRTTExponent is the exponent of the upstreams' round-trip time
	// estimates in their weights in [UpstreamModeLoadBalance]: an upstream's
	// weight is its estimate to the power of -upstreamRTTExponent, so an
	// upstream twice as slow gets a quarter of the share.
	upstreamRTTExponent = 2

	// upstreamRTTBaselineDecay is the time constant of the upstreams'
	// long-term round-trip time moving average of successful exchanges.  The
	// estimate of an upstream that hasn't been used for a while is pulled
	// towards it, so that a past failure's penalty fades even if the upstream
	// is rarely chosen.
	upstreamRTTBaselineDecay = 24 * time.Hour

	// upstreamRTTMaxPullDecay is the upper bound of the time constant of the
	// pull of a failing upstream's estimate, see
	// [upstreamRTTStats.pullDecay].
	upstreamRTTMaxPullDecay = 24 * time.Hour
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

	w := sampleuv.NewWeighted(p.calcWeights(ctx, ups), p.randSrc)
	var errs []error
	for i, ok := w.Take(); ok; i, ok = w.Take() {
		u = ups[i]

		var elapsed time.Duration
		resp, elapsed, err = p.exchange(ctx, u, req)
		if err == nil {
			p.updateRTT(ctx, u.Address(), elapsed, true)

			return resp, u, nil
		}

		errs = append(errs, err)

		p.updateRTT(ctx, u.Address(), p.upstreamTimeout, false)
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

	// baseLast is the time of the latest update of base.  It's zero if there
	// were no updates.
	baseLast time.Time

	// base is the long-term moving average of the round-trip time of
	// successful exchanges in microseconds.  It's zero if there were no
	// updates.
	base float64

	// baseNum is the number of samples in base.
	baseNum float64

	// fails is the number of consecutive failed exchanges.
	fails uint
}

// update returns updated stats after adding given RTT measured at now.  Older
// samples' weight decays by a factor of e per tau.  tau must be positive.
func (stats upstreamRTTStats) update(
	rtt time.Duration,
	now time.Time,
	tau time.Duration,
) (updated upstreamRTTStats) {
	updated = stats
	updated.last = now

	sample := float64(rtt.Microseconds())
	if stats.last.IsZero() {
		updated.ewma = sample

		return updated
	}

	// Clamp to keep the weight within [0, 1] if the clock goes backwards.
	elapsed := max(now.Sub(stats.last), 0)
	w := math.Exp(-elapsed.Seconds() / tau.Seconds())
	updated.ewma = w*stats.ewma + (1-w)*sample

	return updated
}

// updateBase returns updated stats after adding given RTT of a successful
// exchange measured at now to the baseline.  A sample's weight is the larger of
// 1/n, for the n-th sample, and its time-decay weight, so that the baseline is
// the plain average until it holds about tau's worth of samples.  Otherwise the
// first sample would dominate it for a long time.  tau must be positive.
func (stats upstreamRTTStats) updateBase(
	rtt time.Duration,
	now time.Time,
	tau time.Duration,
) (updated upstreamRTTStats) {
	updated = stats
	updated.baseLast = now
	updated.baseNum++

	w := 1 / updated.baseNum
	if !stats.baseLast.IsZero() {
		elapsed := max(now.Sub(stats.baseLast), 0)
		w = max(w, -math.Expm1(-elapsed.Seconds()/tau.Seconds()))
	}

	updated.base = stats.base + w*(float64(rtt.Microseconds())-stats.base)

	return updated
}

// pullDecay returns the time constant of the pull of the upstream's estimate
// or weight given the moving average's time constant tau.  It doubles with
// each consecutive failure after the first one, up to
// [upstreamRTTMaxPullDecay], so that a dead upstream is retried less and less
// often, while a single failure fades at the usual rate.  tau must be
// positive.
func (stats upstreamRTTStats) pullDecay(tau time.Duration) (d time.Duration) {
	d = tau
	for i := uint(1); i < stats.fails && d < upstreamRTTMaxPullDecay; i++ {
		d *= 2
	}

	return max(tau, min(d, upstreamRTTMaxPullDecay))
}

// estimate returns the round-trip time estimate in microseconds at now.  The
// moving average is pulled towards the baseline, if any, as it gets older, by
// a factor of e per [upstreamRTTStats.pullDecay] of tau.  tau must be
// positive.
func (stats upstreamRTTStats) estimate(now time.Time, tau time.Duration) (est float64) {
	if stats.baseNum == 0 {
		return stats.ewma
	}

	age := max(now.Sub(stats.last), 0)
	w := math.Exp(-age.Seconds() / stats.pullDecay(tau).Seconds())

	return w*stats.ewma + (1-w)*stats.base
}

// calcWeights returns the slice of weights, each corresponding to the upstream
// with the same index in the given slice, normalized to sum to 1 before the
// pull described below.  ups elements must not be nil.
//
// An upstream that has been measured but has no baseline, since it never
// answered successfully, has its weight pulled towards 1/len(ups) by a factor
// of e per [upstreamRTTStats.pullDecay] since its latest update.  Otherwise a
// failure on its first exchange would exclude it until restart.
func (p *Proxy) calcWeights(ctx context.Context, ups []upstream.Upstream) (weights []float64) {
	weights = make([]float64, 0, len(ups))
	// pull is the weight of the current value for upstreams without a
	// baseline, -1 for the rest.
	pull := make([]float64, 0, len(ups))

	now := p.time.Now()

	p.rttLock.Lock()
	for _, u := range ups {
		stat := p.upstreamRTTStats[u.Address()]
		switch {
		case stat.ewma == 0:
			// Use 1 as the default weight.
			weights = append(weights, 1)
			pull = append(pull, -1)
		case stat.baseNum == 0:
			weights = append(weights, math.Pow(stat.ewma, -upstreamRTTExponent))
			age := max(now.Sub(stat.last), 0)
			tau := stat.pullDecay(p.upstreamRTTDecay)
			pull = append(pull, math.Exp(-age.Seconds()/tau.Seconds()))
		default:
			est := stat.estimate(now, p.upstreamRTTDecay)
			weights = append(weights, math.Pow(est, -upstreamRTTExponent))
			pull = append(pull, -1)
		}
	}
	p.rttLock.Unlock()

	var sum float64
	for _, w := range weights {
		sum += w
	}

	uniform := 1 / float64(len(ups))
	for i, w := range weights {
		weights[i] = w / sum
		if a := pull[i]; a >= 0 {
			weights[i] = a*weights[i] + (1-a)*uniform
		}
	}

	if p.logger.Enabled(ctx, slog.LevelDebug) {
		p.logger.DebugContext(ctx, "load_balance weights", "weights", formatWeights(ups, weights))
	}

	return weights
}

// formatWeights returns the weights normalized to sum to 1, as space-separated
// address=weight pairs.  ups elements must not be nil.
func formatWeights(ups []upstream.Upstream, weights []float64) (s string) {
	var sum float64
	for _, w := range weights {
		sum += w
	}

	b := &strings.Builder{}
	for i, u := range ups {
		if i > 0 {
			b.WriteByte(' ')
		}

		_, _ = fmt.Fprintf(b, "%s=%.4f", u.Address(), weights[i]/sum)
	}

	return b.String()
}

// updateRTT updates the round-trip time in [upstreamRTTStats] for given
// address.  ok is false if the exchange failed; failures don't affect the
// baseline.
func (p *Proxy) updateRTT(ctx context.Context, address string, rtt time.Duration, ok bool) {
	now := p.time.Now()

	p.rttLock.Lock()
	if p.upstreamRTTStats == nil {
		p.upstreamRTTStats = map[string]upstreamRTTStats{}
	}

	prev := p.upstreamRTTStats[address]
	updated := prev.update(rtt, now, p.upstreamRTTDecay)
	if ok {
		updated = updated.updateBase(rtt, now, upstreamRTTBaselineDecay)
		updated.fails = 0
	} else {
		updated.fails++
	}
	p.upstreamRTTStats[address] = updated
	p.rttLock.Unlock()

	p.logger.DebugContext(
		ctx,
		"updated upstream rtt",
		"upstream", address,
		"rtt", rtt,
		"prev", ewmaDuration(prev.ewma),
		"ewma", ewmaDuration(updated.ewma),
		"base", ewmaDuration(updated.base),
		"fails", updated.fails,
	)
}

// ewmaDuration converts an RTT moving average in microseconds to a duration.
func ewmaDuration(us float64) (d time.Duration) {
	return time.Duration(math.Round(us)) * time.Microsecond
}
