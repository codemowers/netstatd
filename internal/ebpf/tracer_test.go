package ebpf

import (
	"bytes"
	"encoding/binary"
	"testing"

	"netstatd/internal/types"
)

func TestParseByteEvent(t *testing.T) {
	var raw bytes.Buffer
	write := func(v any) {
		t.Helper()
		if err := binary.Write(&raw, binary.LittleEndian, v); err != nil {
			t.Fatalf("binary.Write(%T) error = %v", v, err)
		}
	}

	write(uint64(4096))
	write(uint32(123))
	write(uint16(types.FamilyIPv4))
	write(uint16(34567))
	write(uint16(443))
	write(uint8(types.ProtocolTCP))
	write(uint8(types.ByteDirectionOut))
	write([16]uint8{10: 0xff, 11: 0xff, 12: 10, 13: 0, 14: 0, 15: 1})
	write([16]uint8{10: 0xff, 11: 0xff, 12: 10, 13: 0, 14: 0, 15: 2})

	event, err := parseByteEvent(raw.Bytes())
	if err != nil {
		t.Fatalf("parseByteEvent() error = %v", err)
	}
	if event.ByteCount != 4096 {
		t.Fatalf("ByteCount = %d, want 4096", event.ByteCount)
	}
	if event.Dport != 443 {
		t.Fatalf("Dport = %d, want 443", event.Dport)
	}
	if event.ByteDirection != types.ByteDirectionOut {
		t.Fatalf("ByteDirection = %d, want %d", event.ByteDirection, types.ByteDirectionOut)
	}
	if event.ByteDirectionString() != "out" {
		t.Fatalf("ByteDirectionString() = %q, want out", event.ByteDirectionString())
	}
}
