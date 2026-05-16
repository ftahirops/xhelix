package tpmattest

import "testing"

func TestStubAvailability(t *testing.T) {
	s := &StubAttester{HostID: "h"}
	if s.Available() {
		t.Fatal("stub should report Available=false")
	}
}

func TestStubQuoteRequiresHostID(t *testing.T) {
	s := &StubAttester{}
	if _, err := s.Quote([]byte("n")); err == nil {
		t.Fatal("empty HostID should error")
	}
}

func TestStubQuoteVerifyRoundTrip(t *testing.T) {
	s := &StubAttester{HostID: "host-007"}
	nonce := []byte("challenge-1")
	q, err := s.Quote(nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !q.Stub {
		t.Fatal("expected Stub=true")
	}
	if err := (StubVerifier{}).Verify(q, nonce); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func TestStubVerifyRejectsNonStubQuote(t *testing.T) {
	q := Quote{Stub: false, Nonce: []byte("x")}
	if err := (StubVerifier{}).Verify(q, []byte("x")); err == nil {
		t.Fatal("non-stub quote must not verify")
	}
}

func TestStubVerifyRejectsNonceMismatch(t *testing.T) {
	s := &StubAttester{HostID: "h"}
	q, _ := s.Quote([]byte("a"))
	if err := (StubVerifier{}).Verify(q, []byte("b")); err == nil {
		t.Fatal("nonce mismatch must fail verify")
	}
}

func TestStubVerifyDetectsTamperedPCRs(t *testing.T) {
	s := &StubAttester{HostID: "h"}
	q, _ := s.Quote([]byte("n"))
	q.PCRs[11] = "tampered-digest" // attacker mutates one PCR
	if err := (StubVerifier{}).Verify(q, []byte("n")); err == nil {
		t.Fatal("tampered PCR must invalidate signature")
	}
}

func TestStubVerifyMalformedAKPub(t *testing.T) {
	q := Quote{Stub: true, Nonce: []byte("n"), AKPub: []byte("bogus")}
	if err := (StubVerifier{}).Verify(q, []byte("n")); err == nil {
		t.Fatal("malformed AKPub must not verify")
	}
}

func TestQuotePCRsPopulated(t *testing.T) {
	s := &StubAttester{HostID: "h"}
	q, _ := s.Quote([]byte("n"))
	for _, idx := range []uint32{0, 7, 11} {
		if q.PCRs[idx] == "" {
			t.Errorf("PCR %d empty", idx)
		}
	}
}

func TestHardwareAvailableDefault(t *testing.T) {
	if HardwareAvailable {
		t.Fatal("default build should not advertise hardware")
	}
}
