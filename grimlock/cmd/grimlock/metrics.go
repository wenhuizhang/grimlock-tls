// Process metrics, exposed via expvar at GET /debug/vars when --metrics-addr is
// set. Lock-free atomic counters; safe to bump from any goroutine on the hot path.

package main

import (
	"expvar"
	"sync/atomic"
)

type metricSet struct {
	fullGates         atomic.Uint64 // full attestation gates run
	resumes           atomic.Uint64 // cheap attestation resumptions
	attestFail        atomic.Uint64 // gate/resume failures (server side)
	setupShed         atomic.Uint64 // inbound setups dropped by load-shed
	requestsForwarded atomic.Uint64 // requests forwarded to a local agent
	bytesForwarded    atomic.Uint64 // bytes moved by the data plane
	paymentsAllowed   atomic.Uint64
	paymentsBlocked   atomic.Uint64
	mcpAllowed        atomic.Uint64 // MCP tool calls forwarded (within grant)
	mcpBlocked        atomic.Uint64 // MCP tool calls blocked (unattested/over-grant)
	egressDenied      atomic.Uint64 // connections refused by the egress policy
}

var metrics = &metricSet{}

func init() {
	expvar.Publish("grimlock", expvar.Func(func() any {
		return map[string]uint64{
			"full_gates":         metrics.fullGates.Load(),
			"resumes":            metrics.resumes.Load(),
			"attest_failures":    metrics.attestFail.Load(),
			"setup_shed":         metrics.setupShed.Load(),
			"requests_forwarded": metrics.requestsForwarded.Load(),
			"bytes_forwarded":    metrics.bytesForwarded.Load(),
			"payments_allowed":   metrics.paymentsAllowed.Load(),
			"payments_blocked":   metrics.paymentsBlocked.Load(),
			"mcp_allowed":        metrics.mcpAllowed.Load(),
			"mcp_blocked":        metrics.mcpBlocked.Load(),
			"egress_denied":      metrics.egressDenied.Load(),
		}
	}))
}
