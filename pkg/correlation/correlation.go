// Package correlation provides bounded, non-authorizing evidence join hints.
// It deliberately cannot verify actors, authorization, packet completeness or causality.
package correlation

import "errors"

const Schema = "evidence-service.correlation/v1"

// Observation is metadata only. IDs originate from independently classified
// instrumentation sources. A claimed trace ID never grants collection access.
type Observation struct {
	SessionID       string `json:"session_id"`
	TransportLegID  string `json:"transport_leg_id"`
	ConnectionEpoch string `json:"connection_epoch,omitempty"`
	StreamID        string `json:"stream_id,omitempty"`
	TraceID         string `json:"trace_id,omitempty"`
	Source          string `json:"source"` // e.g., "app" or "network"; no authority implied
}

type Grade string

const (
	Unknown            Grade = "UNKNOWN"
	CorrelatedMetadata Grade = "CORRELATED_METADATA_ONLY"
)

type JoinResult struct {
	Schema               string   `json:"schema"`
	Grade                Grade    `json:"grade"`
	SharedFields         []string `json:"shared_fields,omitempty"`
	VerifiedCausality    bool     `json:"verified_causality"`
	AuthorizationGranted bool     `json:"authorization_granted"`
}

// Join never matches across session or transport-leg boundaries. A stable
// connection epoch is required on BOTH sides: stream IDs may be reused after
// reconnect and cannot identify a connection independently. A verified epoch
// remains correlation metadata only, never causality or authorization.
func Join(a, b Observation) (JoinResult, error) {
	result := JoinResult{Schema: Schema, Grade: Unknown}
	if a.SessionID == "" || b.SessionID == "" || a.TransportLegID == "" || b.TransportLegID == "" {
		return result, errors.New("session and leg identity required")
	}
	if a.SessionID != b.SessionID || a.TransportLegID != b.TransportLegID {
		return result, nil
	}
	// Without an epoch from both sources, even matching stream IDs are
	// ambiguous: HTTP/2/3 IDs can repeat on a second transport connection.
	if a.ConnectionEpoch == "" || b.ConnectionEpoch == "" || a.ConnectionEpoch != b.ConnectionEpoch {
		return result, nil
	}
	shared := []string{"session_id", "transport_leg_id", "connection_epoch"}
	if a.StreamID != "" && b.StreamID != "" {
		if a.StreamID != b.StreamID {
			return result, nil
		}
		shared = append(shared, "stream_id")
	}
	if a.TraceID != "" && b.TraceID != "" && a.TraceID == b.TraceID {
		shared = append(shared, "trace_id_untrusted")
	}
	// Equal scoped connection epochs produce only metadata correlation.
	// Trace IDs are untrusted hints and never upgrade proof or authority.
	result.Grade = CorrelatedMetadata
	result.SharedFields = shared
	return result, nil
}
