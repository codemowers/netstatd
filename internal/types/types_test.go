package types

import "testing"

func TestConnEventLocalRemoteIPs(t *testing.T) {
	tests := []struct {
		name         string
		event        ConnEvent
		wantLocalIP  string
		wantRemoteIP string
	}{
		{
			name: "ipv6 unspecified local and remote",
			event: ConnEvent{
				Family: 10,
			},
			wantLocalIP:  "",
			wantRemoteIP: "",
		},
		{
			name: "ipv4 unspecified local and remote",
			event: ConnEvent{
				Family: 2,
			},
			wantLocalIP:  "",
			wantRemoteIP: "",
		},
		{
			name: "ipv6 values",
			event: ConnEvent{
				Family: 10,
				SaddrV6: [16]uint8{
					0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 1,
				},
				DaddrV6: [16]uint8{
					0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 2,
				},
			},
			wantLocalIP:  "2001:db8::1",
			wantRemoteIP: "2001:db8::2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLocal, gotRemote := tt.event.LocalRemoteIPs()
			if gotLocal != tt.wantLocalIP || gotRemote != tt.wantRemoteIP {
				t.Fatalf("LocalRemoteIPs() = (%q, %q), want (%q, %q)", gotLocal, gotRemote, tt.wantLocalIP, tt.wantRemoteIP)
			}
		})
	}
}
