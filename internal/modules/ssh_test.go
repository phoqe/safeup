package modules

import (
	"testing"
)

func TestSetSshdOption(t *testing.T) {
	tests := []struct {
		name    string
		content string
		key     string
		value   string
		want    string
	}{
		{
			name:    "replace existing",
			content: "Port 22\n",
			key:     "Port",
			value:   "2222",
			want:    "Port 2222\n",
		},
		{
			name:    "replace commented",
			content: "# Port 22\n",
			key:     "Port",
			value:   "2222",
			want:    "Port 2222\n",
		},
		{
			name:    "add new",
			content: "Port 22\n",
			key:     "X11Forwarding",
			value:   "no",
			want:    "Port 22\n\nX11Forwarding no\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := setSshdOption(tt.content, tt.key, tt.value)
			if got != tt.want {
				t.Errorf("setSshdOption() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetSshdOption(t *testing.T) {
	content := "Port 2222\n# X11Forwarding yes\nX11Forwarding no\n"
	tests := []struct {
		key  string
		want string
	}{
		{"Port", "2222"},
		{"X11Forwarding", "no"},
		{"MissingOption", ""},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := getSshdOption(content, tt.key)
			if got != tt.want {
				t.Errorf("getSshdOption(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestGetSshdOptionAllowUsers(t *testing.T) {
	content := "AllowUsers deploy ubuntu\n"
	got := getSshdOption(content, "AllowUsers")
	want := "deploy ubuntu"
	if got != want {
		t.Errorf("getSshdOption(AllowUsers) = %q, want %q", got, want)
	}
}
