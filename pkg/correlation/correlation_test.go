package correlation

import "testing"

func base() Observation {
	return Observation{SessionID: "session-a", TransportLegID: "cloudflare-to-origin", ConnectionEpoch: "epoch-1", StreamID: "stream-3", TraceID: "client-provided"}
}
func TestJoinedMetadataNeverGrantsAuthority(t *testing.T) {
	a, b := base(), base()
	a.Source, b.Source = "app", "network"
	r, err := Join(a, b)
	if err != nil || r.Grade != CorrelatedMetadata || r.VerifiedCausality || r.AuthorizationGranted {
		t.Fatalf("incorrect grade: %+v %v", r, err)
	}
}
func TestForeignSessionRejected(t *testing.T) {
	a, b := base(), base()
	b.SessionID = "session-b"
	r, _ := Join(a, b)
	if r.Grade != Unknown {
		t.Fatal("foreign session joined")
	}
}
func TestForeignLegRejected(t *testing.T) {
	a, b := base(), base()
	b.TransportLegID = "openai-poll"
	r, _ := Join(a, b)
	if r.Grade != Unknown {
		t.Fatal("foreign tunnel leg joined")
	}
}
func TestSeparateMultiplexedStreamsRejected(t *testing.T) {
	a, b := base(), base()
	b.StreamID = "stream-7"
	r, _ := Join(a, b)
	if r.Grade != Unknown {
		t.Fatal("separate HTTP2 streams joined")
	}
}
func TestReconnectedEpochRejected(t *testing.T) {
	a, b := base(), base()
	b.ConnectionEpoch = "epoch-2"
	r, _ := Join(a, b)
	if r.Grade != Unknown {
		t.Fatal("stale connection epoch joined")
	}
}
func TestTraceparentOnlyDoesNotProve(t *testing.T) {
	a, b := base(), base()
	a.ConnectionEpoch = ""
	b.ConnectionEpoch = ""
	a.StreamID = ""
	b.StreamID = ""
	r, _ := Join(a, b)
	if r.Grade != Unknown {
		t.Fatal("traceparent elevated to proof")
	}
}
func TestMissingScopeIsError(t *testing.T) {
	a, b := base(), base()
	a.SessionID = ""
	_, err := Join(a, b)
	if err == nil {
		t.Fatal("unscoped observation accepted")
	}
}
func TestOneSidedStreamDoesNotFabricateIt(t *testing.T) {
	a, b := base(), base()
	b.StreamID = ""
	r, err := Join(a, b)
	if err != nil || r.Grade != CorrelatedMetadata {
		t.Fatalf("connection hint should remain: %+v %v", r, err)
	}
	for _, s := range r.SharedFields {
		if s == "stream_id" {
			t.Fatal("unobserved stream ID fabricated")
		}
	}
}
func TestSameConnectionDifferentRequestsAreNotProven(t *testing.T) {
	a, b := base(), base()
	a.StreamID = ""
	b.StreamID = ""
	a.TraceID = "request-1"
	b.TraceID = "request-2"
	r, _ := Join(a, b)
	if r.Grade != CorrelatedMetadata || r.VerifiedCausality {
		t.Fatalf("connection-only should be weak metadata: %+v", r)
	}
}
