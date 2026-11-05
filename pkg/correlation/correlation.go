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

// Join never matches across session or transport-leg boundaries. An exact
// transport connection and/or stream ID is a correlation hint only; other
// copied fields like traceparent or wall-clock timestamps cannot prove joins.
// A shared TLS connection may multiplex arbitrarily many application streams.
func Join(a, b Observation) (JoinResult, error) {
	result := JoinResult{Schema: Schema, Grade: Unknown}
	if a.SessionID == "" || b.SessionID == "" || a.TransportLegID == "" || b.TransportLegID == "" {
		return result, errors.New("session and leg identity required")
	}
	if a.SessionID != b.SessionID || a.TransportLegID != b.TransportLegID {
		return result, nil
	}
	shared := []string{"session_id", "transport_leg_id"}
	if a.ConnectionEpoch != "" && b.ConnectionEpoch != "" {
		if a.ConnectionEpoch != b.ConnectionEpoch {
			return result, nil
		}
		shared = append(shared, "connection_epoch")
	}
	if a.StreamID != "" && b.StreamID != "" {
		if a.StreamID != b.StreamID {
			return result, nil
		}
		shared = append(shared, "stream_id")
	}
	if a.TraceID != "" && b.TraceID != "" && a.TraceID == b.TraceID {
		shared = append(shared, "trace_id_untrusted")
	}
	// At least one transport-native shared field is required before reporting
	// a correlation; a matching traceparent alone is an untrusted hint.
	if len(shared) > 2 && (contains(shared, "connection_epoch") || contains(shared, "stream_id")) {
		result.Grade = CorrelatedMetadata
		result.SharedFields = shared
	}
	return result, nil
}
func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
