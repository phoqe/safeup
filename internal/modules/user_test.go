package modules

import (
	"strings"
	"testing"
)

func TestListOtherUsersFromReader(t *testing.T) {
	passwd := `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
deploy:x:1000:1000:Deploy:/home/deploy:/bin/bash
ubuntu:x:1001:1001:Ubuntu:/home/ubuntu:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
`
	tests := []struct {
		name   string
		exclude string
		want   []string
	}{
		{
			name:   "exclude deploy",
			exclude: "deploy",
			want:   []string{"ubuntu"},
		},
		{
			name:   "exclude ubuntu",
			exclude: "ubuntu",
			want:   []string{"deploy"},
		},
		{
			name:   "exclude none",
			exclude: "",
			want:   []string{"deploy", "ubuntu"},
		},
		{
			name:   "exclude non-existent",
			exclude: "foo",
			want:   []string{"deploy", "ubuntu"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := listOtherUsersFromReader(strings.NewReader(passwd), tt.exclude)
			if err != nil {
				t.Fatalf("listOtherUsersFromReader() error = %v", err)
			}
			if len(got) != len(tt.want) {
				t.Errorf("listOtherUsersFromReader() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("listOtherUsersFromReader()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
