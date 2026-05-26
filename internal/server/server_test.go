package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"netstatd/internal/types"
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

func TestTrafficSamplesAggregateForConfirmedTCPListeningPort(t *testing.T) {
	s := &Server{
		nodeName:          "node-a",
		options:           Options{EnableByteCountEvents: true, EnableByteCountMetrics: true},
		traffic:           make(map[trafficKey]*trafficAggregate),
		trafficCounters:   make(map[trafficMetricKey]*trafficMetricCounters),
		listeningTCPPorts: make(map[listeningPortKey]struct{}),
	}
	s.rememberListeningTCPPort("10.0.0.1", 443)

	s.recordTrafficSample(types.ByteEvent{
		Protocol:      types.ProtocolTCP,
		Sport:         443,
		Dport:         49152,
		ByteCount:     100,
		ByteDirection: types.ByteDirectionIn,
	}, "10.0.0.1", "10.0.0.2")
	s.recordTrafficSample(types.ByteEvent{
		Protocol:      types.ProtocolTCP,
		Sport:         443,
		Dport:         49152,
		ByteCount:     50,
		ByteDirection: types.ByteDirectionOut,
	}, "10.0.0.1", "10.0.0.2")

	samples := s.drainTrafficSamples(time.Date(2026, 5, 19, 0, 0, 0, 0, time.UTC))
	if len(samples) != 1 {
		t.Fatalf("drainTrafficSamples() returned %d samples, want 1", len(samples))
	}
	sample := samples[0]
	if sample.Type() != "traffic.sample" {
		t.Fatalf("sample.Type() = %q, want traffic.sample", sample.Type())
	}
	if sample.BytesIn != 100 || sample.BytesOut != 50 {
		t.Fatalf("sample bytes = in:%d out:%d, want in:100 out:50", sample.BytesIn, sample.BytesOut)
	}
	if sample.RemotePort != 49152 {
		t.Fatalf("sample RemotePort = %d, want 49152", sample.RemotePort)
	}
	if sample.SamplesIn != 1 || sample.SamplesOut != 1 {
		t.Fatalf("sample counts = in:%d out:%d, want in:1 out:1", sample.SamplesIn, sample.SamplesOut)
	}
	metricCounters := s.trafficCounters[trafficMetricKey{
		Protocol:  types.ProtocolTCP,
		LocalIP:   "10.0.0.1",
		LocalPort: 443,
		RemoteIP:  "10.0.0.2",
	}]
	if metricCounters == nil || metricCounters.BytesIn != 100 || metricCounters.BytesOut != 50 {
		t.Fatalf("traffic metric counters = %#v, want in:100 out:50", metricCounters)
	}
}

func TestTrafficSamplesDropTCPWithoutConfirmedListeningPort(t *testing.T) {
	s := &Server{
		nodeName:          "node-a",
		options:           Options{EnableByteCountEvents: true, EnableByteCountMetrics: true},
		traffic:           make(map[trafficKey]*trafficAggregate),
		trafficCounters:   make(map[trafficMetricKey]*trafficMetricCounters),
		listeningTCPPorts: make(map[listeningPortKey]struct{}),
	}

	s.recordTrafficSample(types.ByteEvent{
		Protocol:      types.ProtocolTCP,
		Sport:         49152,
		ByteCount:     100,
		ByteDirection: types.ByteDirectionOut,
	}, "10.0.0.1", "10.0.0.2")

	if samples := s.drainTrafficSamples(time.Now()); len(samples) != 0 {
		t.Fatalf("drainTrafficSamples() returned %d samples, want 0", len(samples))
	}
}

func TestTrafficSamplesAggregateUDPWithoutListeningGate(t *testing.T) {
	s := &Server{
		nodeName:          "node-a",
		options:           Options{EnableByteCountEvents: true, EnableByteCountMetrics: true},
		traffic:           make(map[trafficKey]*trafficAggregate),
		trafficCounters:   make(map[trafficMetricKey]*trafficMetricCounters),
		listeningTCPPorts: make(map[listeningPortKey]struct{}),
	}

	s.recordTrafficSample(types.ByteEvent{
		Protocol:      types.ProtocolUDP,
		Sport:         5353,
		Dport:         44444,
		ByteCount:     25,
		ByteDirection: types.ByteDirectionIn,
	}, "10.0.0.1", "10.0.0.2")

	samples := s.drainTrafficSamples(time.Now())
	if len(samples) != 1 {
		t.Fatalf("drainTrafficSamples() returned %d samples, want 1", len(samples))
	}
	if samples[0].Protocol != "UDP" || samples[0].BytesIn != 25 {
		t.Fatalf("sample = %#v, want UDP bytesIn 25", samples[0])
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

func TestShouldOmitMetadataEvent(t *testing.T) {
	s := &Server{options: Options{}}

	omitted := []Event{
		HostInfoEvent{EventType: "host.info"},
		ContainerAddedEvent{EventType: "container.added"},
		ContainerMetainfoEvent{EventType: "container.metainfo"},
		ImageMetainfoEvent{EventType: "image.metainfo"},
		JSONEvent{Data: []byte(`{"type":"container.deleted"}`)},
	}
	for _, event := range omitted {
		if !s.shouldOmitMetadataEvent(event) {
			t.Fatalf("shouldOmitMetadataEvent(%q) = false, want true", event.Type())
		}
	}

	kept := []Event{
		ConnectionEvent{EventType: "connection.event"},
		ProcessMetainfoEvent{EventType: "process.metainfo"},
		JSONEvent{Data: []byte(`{"type":"port.listening"}`)},
	}
	for _, event := range kept {
		if s.shouldOmitMetadataEvent(event) {
			t.Fatalf("shouldOmitMetadataEvent(%q) = true, want false", event.Type())
		}
	}
}

func TestShouldOmitMetadataEventsRespectsSplitOptions(t *testing.T) {
	s := &Server{options: Options{
		EnableHostInfo:          true,
		EnableContainerEvents:   true,
		EnableContainerMetainfo: true,
		EnableImageMetainfo:     true,
	}}

	kept := []Event{
		HostInfoEvent{EventType: "host.info"},
		ContainerAddedEvent{EventType: "container.added"},
		ContainerMetainfoEvent{EventType: "container.metainfo"},
		ImageMetainfoEvent{EventType: "image.metainfo"},
		JSONEvent{Data: []byte(`{"type":"container.deleted"}`)},
	}
	for _, event := range kept {
		if s.shouldOmitMetadataEvent(event) {
			t.Fatalf("shouldOmitMetadataEvent(%q) = true, want false", event.Type())
		}
	}
}

func TestShouldOmitMetadataEventsSplitsContainerLifecycleAndMetainfo(t *testing.T) {
	s := &Server{options: Options{
		EnableContainerEvents:   true,
		EnableContainerMetainfo: false,
	}}

	if s.shouldOmitMetadataEvent(ContainerAddedEvent{EventType: "container.added"}) {
		t.Fatal("container.added omitted when container events are enabled")
	}
	if !s.shouldOmitMetadataEvent(ContainerMetainfoEvent{EventType: "container.metainfo"}) {
		t.Fatal("container.metainfo kept when container metainfo is disabled")
	}
}
