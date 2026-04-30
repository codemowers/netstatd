package containerd

import "testing"

func TestExtractPodUIDFromCgroup(t *testing.T) {
	tests := []struct {
		name   string
		cgroup string
		want   string
	}{
		{
			name:   "guaranteed qos slice",
			cgroup: "0::/kubepods.slice/kubepods-pod1d2f838d_4a2e_4f27_be9e_ce7f8a4a466f.slice/cri-containerd-deadbeef.scope",
			want:   "1d2f838d-4a2e-4f27-be9e-ce7f8a4a466f",
		},
		{
			name:   "burstable qos slice",
			cgroup: "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1d2f838d_4a2e_4f27_be9e_ce7f8a4a466f.slice/cri-containerd-deadbeef.scope",
			want:   "1d2f838d-4a2e-4f27-be9e-ce7f8a4a466f",
		},
		{
			name:   "besteffort qos slice",
			cgroup: "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod1d2f838d_4a2e_4f27_be9e_ce7f8a4a466f.slice/cri-containerd-deadbeef.scope",
			want:   "1d2f838d-4a2e-4f27-be9e-ce7f8a4a466f",
		},
		{
			name:   "no pod uid present",
			cgroup: "0::/system.slice/sshd.service",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExtractPodUIDFromCgroup(tt.cgroup); got != tt.want {
				t.Fatalf("ExtractPodUIDFromCgroup(%q) = %q, want %q", tt.cgroup, got, tt.want)
			}
		})
	}
}

func TestExtractContainerLabelsCopiesAllLabels(t *testing.T) {
	labels := map[string]string{
		"io.cri-containerd.kind":               "container",
		"io.kubernetes.pod.name":               "minio-1",
		"io.kubernetes.pod.label.app":          "minio",
		"io.kubernetes.container.restartCount": "0",
	}

	got := extractContainerLabels(labels)
	if len(got) != len(labels) {
		t.Fatalf("label count = %d, want %d", len(got), len(labels))
	}
	for k, want := range labels {
		if got[k] != want {
			t.Fatalf("label %q = %q, want %q", k, got[k], want)
		}
	}

	got["io.kubernetes.pod.name"] = "changed"
	if labels["io.kubernetes.pod.name"] != "minio-1" {
		t.Fatal("extractContainerLabels returned alias of input map")
	}
}
