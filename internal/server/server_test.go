package server

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseProcessNameFromStatus(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    string
		wantErr bool
	}{
		{
			name: "name field",
			data: []byte("Name:\tcurl\nUmask:\t0022\n"),
			want: "curl",
		},
		{
			name:    "missing name field",
			data:    []byte("Umask:\t0022\n"),
			wantErr: true,
		},
		{
			name:    "empty name field",
			data:    []byte("Name:\t\nUmask:\t0022\n"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseProcessNameFromStatus(tt.data, "status")
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseProcessNameFromStatus() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseProcessNameFromStatus() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("parseProcessNameFromStatus() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseCgroupSlice(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    string
		wantErr bool
	}{
		{
			name: "first line",
			data: []byte("0::/kubepods.slice/pod.slice\n1:name=systemd:/ignored\n"),
			want: "0::/kubepods.slice/pod.slice",
		},
		{
			name:    "empty file",
			data:    []byte(""),
			wantErr: true,
		},
		{
			name:    "whitespace only",
			data:    []byte("\n\t\n"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCgroupSlice(tt.data, "cgroup")
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseCgroupSlice() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCgroupSlice() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("parseCgroupSlice() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConnectionEventJSONOmitsPID(t *testing.T) {
	event := ConnectionEvent{
		EventType:  "connection.event",
		Timestamp:  "2026-04-29T00:00:00Z",
		Protocol:   "TCP",
		State:      "ESTABLISHED",
		SockCookie: 1,
		LocalIP:    "10.0.0.1",
		RemoteIP:   "10.0.0.2",
	}

	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if strings.Contains(string(payload), `"pid"`) {
		t.Fatalf("connection.event JSON contains pid field: %s", payload)
	}
}

func TestConnectionAcceptedEventRequiresPIDJSON(t *testing.T) {
	event := ConnectionAcceptedEvent{
		ConnectionEvent: ConnectionEvent{
			EventType:  "connection.accepted",
			Timestamp:  "2026-04-29T00:00:00Z",
			Protocol:   "TCP",
			State:      "ESTABLISHED",
			SockCookie: 1,
			LocalIP:    "10.0.0.1",
			RemoteIP:   "10.0.0.2",
		},
		PID: 1234,
	}

	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if !strings.Contains(string(payload), `"pid":1234`) {
		t.Fatalf("connection.accepted JSON missing pid field: %s", payload)
	}
}

func TestCreateProcessMetainfoEventAllowsPartialResolution(t *testing.T) {
	s := &Server{nodeName: "node-a"}

	event := s.createProcessMetainfoEventFromResolved(1234, "", 0, "")
	if event == nil {
		t.Fatalf("createProcessMetainfoEventFromResolved() = nil, want event")
	}
	if event.PID != 1234 {
		t.Fatalf("PID = %d, want 1234", event.PID)
	}
	if event.NetNS != 0 {
		t.Fatalf("NetNS = %d, want 0", event.NetNS)
	}
	if event.CgroupSlice != "" {
		t.Fatalf("CgroupSlice = %q, want empty", event.CgroupSlice)
	}
	if event.IsHostNetNS {
		t.Fatalf("IsHostNetNS = true, want false for unresolved netns")
	}
}

func TestCreateProcessMetainfoEventDropsContainerWithoutNetNS(t *testing.T) {
	s := &Server{nodeName: "node-a"}
	cgroupSlice := "0::/kubepods.slice/kubepods-pod1d2f838d_4a2e_4f27_be9e_ce7f8a4a466f.slice/cri-containerd-deadbeef.scope"

	event := s.createProcessMetainfoEventFromResolved(1234, "worker", 0, cgroupSlice)
	if event != nil {
		t.Fatalf("createProcessMetainfoEventFromResolved() = %#v, want nil", event)
	}
}
