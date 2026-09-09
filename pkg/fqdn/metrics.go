package fqdn

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var stageDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "awsnodeagent_fqdn_stage_duration_seconds",
	Help:    "Time spent holding DNS responses, programming, and revoking FQDN permissions.",
	Buckets: prometheus.DefBuckets,
}, []string{"stage", "result"})

// Observe uses only code-owned stage names. Names, addresses and endpoint IDs
// belong in opt-in diagnostics, never metric labels.
func Observe(stage string, started time.Time, err error) {
	switch stage {
	case "publication", "revocation", "expiry", "programming", "attachment", "transport", "upstream", "authenticate", "publish", "recovery":
	default:
		stage = "other"
	}
	result := "success"
	if err != nil {
		result = "failure"
	}
	stageDuration.WithLabelValues(stage, result).Observe(time.Since(started).Seconds())
}

// RegisterMetrics adds FQDN diagnostics to the nodeagent's existing registry.
// Snapshot callbacks must return promptly; they do not access kernel maps.
func RegisterMetrics(reg prometheus.Registerer, state func() Stats, proxy func() ProxyStats, ready func() bool) error {
	collectors := []prometheus.Collector{stageDuration,
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "awsnodeagent_fqdn_proxy_ready", Help: "Whether DNS listeners and host steering are ready."}, func() float64 {
			if ready() {
				return 1
			}
			return 0
		}),
	}
	for _, metric := range []struct {
		name, help string
		value      func(Stats) float64
	}{
		{"endpoints", "Enrolled endpoint lifetimes.", func(s Stats) float64 { return float64(s.Endpoints) }},
		{"rules", "Compiled endpoint-specific rules.", func(s Stats) float64 { return float64(s.Rules) }},
		{"observations", "Retained bounded DNS observations.", func(s Stats) float64 { return float64(s.Observations) }},
		{"addresses", "Retained learned addresses.", func(s Stats) float64 { return float64(s.Addresses) }},
		{"grants", "Retained dynamic L4 grants.", func(s Stats) float64 { return float64(s.Grants) }},
	} {
		collectors = append(collectors, prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "awsnodeagent_fqdn_" + metric.name, Help: metric.help}, func() float64 { return metric.value(state()) }))
	}
	for _, metric := range []struct {
		name, help string
		value      func(Stats) float64
	}{
		{"admissions_total", "Successfully published FQDN answers.", func(s Stats) float64 { return float64(s.Admissions) }},
		{"failures_total", "Failed FQDN admissions.", func(s Stats) float64 { return float64(s.Failures) }},
		{"revocations_total", "Observed FQDN revocations.", func(s Stats) float64 { return float64(s.Revocations) }},
		{"expired_total", "Expired DNS observations reclaimed.", func(s Stats) float64 { return float64(s.Expired) }},
	} {
		collectors = append(collectors, prometheus.NewCounterFunc(prometheus.CounterOpts{Name: "awsnodeagent_fqdn_" + metric.name, Help: metric.help}, func() float64 { return metric.value(state()) }))
	}
	for _, metric := range []struct {
		name, help string
		value      func(ProxyStats) float64
	}{
		{"pending_requests", "In-flight DNS exchanges.", func(s ProxyStats) float64 { return float64(s.Pending) }},
		{"pending_bytes", "Reserved wire bytes for in-flight DNS exchanges.", func(s ProxyStats) float64 { return float64(s.PendingBytes) }},
		{"tcp_sockets", "Accepted persistent DNS TCP connections.", func(s ProxyStats) float64 { return float64(s.TCPSockets) }},
	} {
		collectors = append(collectors, prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "awsnodeagent_fqdn_" + metric.name, Help: metric.help}, func() float64 { return metric.value(proxy()) }))
	}
	for _, metric := range []struct {
		name, help string
		value      func(ProxyStats) float64
	}{
		{"upstream_failures_total", "Resolver transport failures.", func(s ProxyStats) float64 { return float64(s.UpstreamFailures) }},
		{"authentication_failures_total", "DNS exchanges without current trusted provenance.", func(s ProxyStats) float64 { return float64(s.AuthenticationFailures) }},
		{"capacity_failures_total", "DNS exchanges rejected by resource budgets.", func(s ProxyStats) float64 { return float64(s.CapacityFailures) }},
	} {
		collectors = append(collectors, prometheus.NewCounterFunc(prometheus.CounterOpts{Name: "awsnodeagent_fqdn_" + metric.name, Help: metric.help}, func() float64 { return metric.value(proxy()) }))
	}
	for _, collector := range collectors {
		if err := reg.Register(collector); err != nil {
			return err
		}
	}
	return nil
}
