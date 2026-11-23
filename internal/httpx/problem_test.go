package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("body is not JSON: %v\n%s", err, rec.Body.String())
	}
	return m
}

func TestWriteRendersProblem(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	p := Conflict("dependent_services_running", "cannot unmount %s", "/pool").With("active_deps", []string{"a.service", "b.service"})
	Write(rec, p)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content-type = %q", ct)
	}
	m := decode(t, rec)
	want := map[string]any{
		"type":   "about:blank",
		"title":  "Conflict",
		"status": float64(409),
		"detail": "cannot unmount /pool",
		"code":   "dependent_services_running",
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s = %v, want %v", k, m[k], v)
		}
	}
	deps, _ := m["active_deps"].([]any)
	if len(deps) != 2 || deps[0] != "a.service" {
		t.Errorf("active_deps = %v", m["active_deps"])
	}
}

func TestWriteExtCannotOverrideStandardMembers(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	p := NotFound("unknown_unit", "no unit %q", "x").With("status", 200).With("title", "forged")
	Write(rec, p)
	m := decode(t, rec)
	if m["status"] != float64(404) || m["title"] != "Not Found" {
		t.Errorf("standard members overridden: %v", m)
	}
}

func TestHelpersStatusAndTitle(t *testing.T) {
	t.Parallel()
	cases := []struct {
		p      *Problem
		status int
	}{
		{BadRequest("c", ""), 400},
		{NotFound("c", ""), 404},
		{Conflict("c", ""), 409},
		{Internal("c", ""), 500},
		{BadGateway("c", ""), 502},
		{Unavailable("c", ""), 503},
	}
	for _, c := range cases {
		if c.p.Status != c.status || c.p.Title != http.StatusText(c.status) {
			t.Errorf("%+v: want status %d title %q", c.p, c.status, http.StatusText(c.status))
		}
		if c.p.Detail != "" {
			t.Errorf("empty format should give empty detail, got %q", c.p.Detail)
		}
	}
}

func TestResponseErrorMapsProblem(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/services/x/start", nil)
	// Wrapped: handlers may add context with %w.
	err := fmt.Errorf("start: %w", Conflict("constraint_unmet", "mount /pool missing"))
	ResponseError(rec, r, err)

	if rec.Code != 409 {
		t.Fatalf("status = %d", rec.Code)
	}
	m := decode(t, rec)
	if m["code"] != "constraint_unmet" || m["instance"] != "/api/services/x/start" {
		t.Errorf("body = %v", m)
	}
}

func TestResponseErrorHidesGenericErrors(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/storage", nil)
	ResponseError(rec, r, errors.New("exec bcachefs: /dev/sda1 permission denied (secret detail)"))

	if rec.Code != 500 {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "secret detail") || strings.Contains(rec.Body.String(), "bcachefs") {
		t.Fatalf("internal detail leaked: %s", rec.Body.String())
	}
	m := decode(t, rec)
	if m["code"] != "internal" || m["title"] != "Internal Server Error" {
		t.Errorf("body = %v", m)
	}
	if _, ok := m["detail"]; ok {
		t.Errorf("detail must be absent: %v", m)
	}
}

func TestResponseErrorStaysQuietWhenTheClientLeft(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/overview", nil).WithContext(ctx)
	ResponseError(rec, r, context.Canceled)
	if rec.Body.Len() != 0 {
		t.Fatalf("wrote a problem to a client that is gone: %s", rec.Body.String())
	}
}

func TestRequestErrorIs400(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	RequestError(rec, httptest.NewRequest("POST", "/api/x", nil), errors.New("unexpected EOF"))
	if rec.Code != 400 {
		t.Fatalf("status = %d", rec.Code)
	}
	if m := decode(t, rec); m["code"] != "bad_request" {
		t.Errorf("body = %v", m)
	}
}

func TestRequestErrorBodyTooLarge(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	RequestError(rec, httptest.NewRequest("POST", "/api/x", nil), &http.MaxBytesError{Limit: 10})
	if rec.Code != 413 {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestParamErrorIs400(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	ParamError(rec, httptest.NewRequest("GET", "/api/services/events?limit=abc", nil), errors.New("invalid format for parameter limit"))
	if rec.Code != 400 || rec.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("status %d ct %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func TestNotFoundHandler(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	NotFoundHandler.ServeHTTP(rec, httptest.NewRequest("GET", "/api/nope", nil))
	if rec.Code != 404 {
		t.Fatalf("status = %d", rec.Code)
	}
	if m := decode(t, rec); m["code"] != "not_found" {
		t.Errorf("body = %v", m)
	}
}
