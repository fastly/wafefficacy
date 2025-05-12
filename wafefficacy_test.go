package main

import (
	"testing"
)

func TestSanitizeDates(t *testing.T) {
	s := "Date: Fri, 09 May 2025 03:35:19 GMT"
	want := "Date: Thu, 01 Jan 1970 00:00:00 GMT"
	got := sanitizeDates(s)
	if got != want {
		t.Errorf("s: %s, want: %s, got: %s", s, want, got)
	}
}
