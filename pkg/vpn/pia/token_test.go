package pia

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestToken(t *testing.T) {
	status, body := http.StatusOK, `{"token":"abc"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if u, p := r.FormValue("username"), r.FormValue("password"); u != "user" || p != "secret" {
			t.Errorf("credentials = %q/%q", u, p)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := &Client{user: "user", pwd: "secret"}

	token, err := c.requestToken(srv.Client(), srv.URL)
	if err != nil || token != "abc" {
		t.Fatalf("token = %q, err = %v", token, err)
	}

	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"unauthorized", http.StatusUnauthorized, `{"token":"abc"}`},
		{"empty token", http.StatusOK, `{}`},
		{"malformed", http.StatusOK, `not json`},
	} {
		status, body = tc.status, tc.body
		if _, err := c.requestToken(srv.Client(), srv.URL); err == nil {
			t.Errorf("%s: expected an error", tc.name)
		}
	}
}
