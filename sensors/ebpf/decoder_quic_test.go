package ebpf

import (
	"encoding/binary"
	"testing"

	"github.com/xhelix/xhelix/pkg/model"
)

// buildNetBytesPayload builds an XH_EV_NET_BYTES payload (post-header):
// family(4)|daddr(16)|dport(2)|sport(2)|bytes(4)|dir(1)|_pad(3).
func buildNetBytesPayload(quicFlag byte) []byte {
	b := make([]byte, 4+16+2+2+4+1+3)
	binary.LittleEndian.PutUint32(b[0:4], 2) // AF_INET
	b[19] = 8                                 // daddr last octet (8.8.8.8-ish)
	binary.LittleEndian.PutUint16(b[20:22], 443)
	binary.LittleEndian.PutUint32(b[24:28], 1200)
	b[28] = 0        // dir out
	b[29] = quicFlag // _pad[0]
	return b
}

func TestDecodeNetBytes_QUICFlag(t *testing.T) {
	ev := &model.Event{Tags: map[string]string{}}
	decodeNetBytesEvent(buildNetBytesPayload(1), ev)
	if ev.Tags["quic_confirmed"] != "1" {
		t.Fatalf("quic flag 1 -> tag %q, want \"1\"", ev.Tags["quic_confirmed"])
	}
	ev2 := &model.Event{Tags: map[string]string{}}
	decodeNetBytesEvent(buildNetBytesPayload(0), ev2)
	if _, ok := ev2.Tags["quic_confirmed"]; ok {
		t.Fatalf("quic flag 0 should not set tag, got %q", ev2.Tags["quic_confirmed"])
	}
}
