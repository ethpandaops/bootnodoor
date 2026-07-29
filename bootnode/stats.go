package bootnode

import (
	"time"

	v4protocol "github.com/ethpandaops/bootnodoor/discv4/protocol"
	"github.com/ethpandaops/bootnodoor/discv5/session"
	"github.com/ethpandaops/bootnodoor/services"
	"github.com/ethpandaops/bootnodoor/transport"
)

// Stats aggregates the live counters the web UI renders. Everything here is
// summed across both layers (EL and CL lookup services) and across all
// discovery identities, of which there are two when separate EL and CL keys
// are configured.
type Stats struct {
	Lookups  services.LookupStats
	Ping     services.PingStats
	Discv5   Discv5Stats
	Discv4   v4protocol.HandlerStats
	HasV4    bool
	Sessions session.Stats
	Packets  transport.MetricsSnapshot
}

// Discv5Stats is the deliberate subset of protocol.HandlerStats the web UI renders, summed per identity.
type Discv5Stats struct {
	InvalidPackets    int
	FilteredResponses int
	FindNodeReceived  int
	PendingHandshakes int
	PendingChallenges int
}

// GetStats returns a snapshot of the service's discovery counters.
func (s *Service) GetStats() Stats {
	var out Stats

	for _, ls := range []*services.LookupService{s.elLookupService, s.clLookupService} {
		if ls == nil {
			continue
		}
		l := ls.GetStats()
		out.Lookups.LookupsStarted += l.LookupsStarted
		out.Lookups.LookupsCompleted += l.LookupsCompleted
		out.Lookups.LookupsFailed += l.LookupsFailed
		out.Lookups.NodesDiscovered += l.NodesDiscovered
		out.Lookups.LookupsV5 += l.LookupsV5
		out.Lookups.LookupsV4 += l.LookupsV4
	}

	var totalRTT time.Duration
	rttSamples := 0
	seenTransports := make(map[*transport.UDPTransport]bool)

	for _, id := range s.identities {
		if id.pingService != nil {
			p := id.pingService.GetStats()
			out.Ping.PingsSent += p.PingsSent
			out.Ping.PongsReceived += p.PongsReceived
			out.Ping.PingTimeouts += p.PingTimeouts
			out.Ping.PingsV5 += p.PingsV5
			out.Ping.PingsV4 += p.PingsV4
			if p.AverageRTT > 0 {
				totalRTT += p.AverageRTT
				rttSamples++
			}
		}

		if id.discv5Service != nil {
			if h := id.discv5Service.Handler(); h != nil {
				d := h.GetStats()
				out.Discv5.InvalidPackets += d.InvalidPackets
				out.Discv5.FilteredResponses += d.FilteredResponses
				out.Discv5.FindNodeReceived += d.FindNodeReceived
				out.Discv5.PendingHandshakes += d.PendingHandshakes
				out.Discv5.PendingChallenges += d.PendingChallenges
			}
			if c := id.discv5Service.Sessions(); c != nil {
				sess := c.GetStats()
				out.Sessions.Total += sess.Total
				out.Sessions.Active += sess.Active
				out.Sessions.Expired += sess.Expired
			}
		}

		// Identities sharing a bind port share one socket, so its packet
		// counters must only be added once.
		if id.transport != nil && !seenTransports[id.transport] {
			seenTransports[id.transport] = true
			m := id.transport.Metrics().Snapshot()
			out.Packets.PacketsSent += m.PacketsSent
			out.Packets.PacketsReceived += m.PacketsReceived
			out.Packets.PacketsDropped += m.PacketsDropped
			out.Packets.BytesSent += m.BytesSent
			out.Packets.BytesReceived += m.BytesReceived
			out.Packets.SendErrors += m.SendErrors
			out.Packets.ReceiveErrors += m.ReceiveErrors
			out.Packets.RateLimited += m.RateLimited
			out.Packets.PacketsFellThrough += m.PacketsFellThrough
			out.Packets.PacketsUnhandled += m.PacketsUnhandled
		}
	}

	if rttSamples > 0 {
		out.Ping.AverageRTT = totalRTT / time.Duration(rttSamples)
	}
	if out.Ping.PingsSent > 0 {
		out.Ping.SuccessRate = float64(out.Ping.PongsReceived) / float64(out.Ping.PingsSent) * 100
	}

	if v4 := s.getV4Service(); v4 != nil {
		if h := v4.Handler(); h != nil {
			out.Discv4 = h.GetStats()
			out.HasV4 = true
		}
	}

	return out
}
