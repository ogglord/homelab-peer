package peerclient_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ogglord/homelab-peer/internal/peerclient"
)

// The run token comes from Client.RunToken only, never the environment: a
// test run inside a real peer run must not leak its token to a fake hub.
func TestSendRunTokenHeaderFromField(t *testing.T) {
	t.Setenv(peerclient.EnvRunToken, "env-token-must-not-be-sent")
	for _, tc := range []struct {
		name, token string
	}{{"with token", "field-token"}, {"without token", ""}} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Header.Values("X-Peer-Run-Token")
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			}))
			defer srv.Close()
			c, err := peerclient.New(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			c.RunToken = tc.token
			_, _ = c.Send(context.Background(), peerclient.Send{ID: "x", Kind: peerclient.KindStatus, Target: "t", Text: "hi"})
			switch {
			case tc.token == "" && len(got) != 0:
				t.Fatalf("X-Peer-Run-Token sent without RunToken: %d value(s)", len(got))
			case tc.token != "" && (len(got) != 1 || got[0] != tc.token):
				t.Fatalf("X-Peer-Run-Token = %q, want the field value", got)
			}
		})
	}
}
