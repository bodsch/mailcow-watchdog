package store

import (
	"testing"
	"time"

	"bodsch.me/mailcow-watchdog/internal/health"
)

// The mailcow UI parses these records, so their exact shape is part of the
// contract. Both were produced by watchdog.sh as hand-built JSON with every
// value quoted, numbers included.
func TestEncodeProgressMatchesTheShellFormat(t *testing.T) {
	at := time.Unix(1767225600, 0)
	snapshot := health.Snapshot{
		Service:   "Nginx",
		Threshold: 5,
		Remaining: 3,
		Trend:     -2,
		Percent:   60,
	}

	got, err := EncodeProgress(snapshot, at)
	if err != nil {
		t.Fatalf("EncodeProgress: %v", err)
	}

	want := `{"time":"1767225600","service":"Nginx","lvl":"60","hpnow":"3","hptotal":"5","hpdiff":"-2"}`
	if string(got) != want {
		t.Errorf("EncodeProgress =\n  %s\nwant\n  %s", got, want)
	}
}

func TestEncodeMessageMatchesTheShellFormat(t *testing.T) {
	at := time.Unix(1767225600, 0)

	got, err := EncodeMessage("Nginx hit error limit", at)
	if err != nil {
		t.Fatalf("EncodeMessage: %v", err)
	}

	want := `{"time":"1767225600","message":"Nginx hit error limit"}`
	if string(got) != want {
		t.Errorf("EncodeMessage =\n  %s\nwant\n  %s", got, want)
	}
}

// watchdog.sh ran messages through `tr '\r\n%&;$"_[]{}-' ' '` before storing
// them. The UI has been reading them that way ever since.
func TestSanitize(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain text is untouched", "Nginx hit error limit", "Nginx hit error limit"},
		{"newlines become spaces", "line one\nline two", "line one line two"},
		{"carriage returns become spaces", "a\rb", "a b"},
		{"quotes become spaces", `he said "no"`, "he said  no "},
		{"shell metacharacters become spaces", "a$b&c;d%e", "a b c d e"},
		{"brackets and braces become spaces", "a[b]c{d}e", "a b c d e"},
		{"hyphens and underscores become spaces", "php-fpm_mailcow", "php fpm mailcow"},
		{"unicode survives", "Zertifikat läuft ab", "Zertifikat läuft ab"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Sanitize(tc.in); got != tc.want {
				t.Errorf("Sanitize(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// A message that would otherwise break the record is neutralised before the
// encoder ever sees it, which is why the output has no escape sequences in it.
func TestEncodeMessageNeutralisesQuotes(t *testing.T) {
	got, err := EncodeMessage(`container "nginx-mailcow" died`, time.Unix(0, 0))
	if err != nil {
		t.Fatalf("EncodeMessage: %v", err)
	}

	want := `{"time":"0","message":"container  nginx mailcow  died"}`
	if string(got) != want {
		t.Errorf("EncodeMessage =\n  %s\nwant\n  %s", got, want)
	}
}
