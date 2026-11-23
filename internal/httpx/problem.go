// Package httpx renders RFC 9457 problem+json errors with a machine-readable
// code, and server-sent-event streams.
package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"syscall"
)

// ContentTypeProblem is the media type of every error body.
const ContentTypeProblem = "application/problem+json"

var log = slog.Default().With("component", "httpx")

// Problem is an RFC 9457 problem-details error. It implements error so a
// handler can return it directly; ResponseError renders it.
//
// Code is the machine-readable discriminator clients branch on
// (unknown_unit, constraint_unmet, ...). Ext members are merged into the top
// level of the JSON object (e.g. "active_deps"); they cannot override the
// standard members.
type Problem struct {
	Status int
	Code   string
	Title  string
	Detail string
	Ext    map[string]any
}

// Error implements error.
func (p *Problem) Error() string {
	if p.Detail != "" {
		return fmt.Sprintf("%d %s: %s", p.Status, p.Title, p.Detail)
	}
	return fmt.Sprintf("%d %s", p.Status, p.Title)
}

// With returns a copy of p carrying one extension member.
func (p *Problem) With(key string, value any) *Problem {
	cp := *p
	cp.Ext = make(map[string]any, len(p.Ext)+1)
	for k, v := range p.Ext {
		cp.Ext[k] = v
	}
	cp.Ext[key] = value
	return &cp
}

func newProblem(status int, code, format string, args ...any) *Problem {
	p := &Problem{Status: status, Code: code, Title: http.StatusText(status)}
	if format != "" {
		p.Detail = fmt.Sprintf(format, args...)
	}
	return p
}

// BadRequest is a 400.
func BadRequest(code, f string, a ...any) *Problem {
	return newProblem(http.StatusBadRequest, code, f, a...)
}

// Unauthorized is a 401: the caller's identity could not be established.
func Unauthorized(code, f string, a ...any) *Problem {
	return newProblem(http.StatusUnauthorized, code, f, a...)
}

// Forbidden is a 403: the caller is known but not allowed.
func Forbidden(code, f string, a ...any) *Problem {
	return newProblem(http.StatusForbidden, code, f, a...)
}

// NotFound is a 404.
func NotFound(code, f string, a ...any) *Problem {
	return newProblem(http.StatusNotFound, code, f, a...)
}

// Conflict is a 409.
func Conflict(code, f string, a ...any) *Problem {
	return newProblem(http.StatusConflict, code, f, a...)
}

// Unprocessable is a 422: a well-formed request the target cannot honour.
func Unprocessable(code, f string, a ...any) *Problem {
	return newProblem(http.StatusUnprocessableEntity, code, f, a...)
}

// Unavailable is a 503.
func Unavailable(code, f string, a ...any) *Problem {
	return newProblem(http.StatusServiceUnavailable, code, f, a...)
}

// BadGateway is a 502.
func BadGateway(code, f string, a ...any) *Problem {
	return newProblem(http.StatusBadGateway, code, f, a...)
}

// Internal is a 500 whose detail is sent to the client as written. Prefer
// returning a plain error: ResponseError logs it and hides the detail.
func Internal(code, f string, a ...any) *Problem {
	return newProblem(http.StatusInternalServerError, code, f, a...)
}

// Write renders p as application/problem+json.
func Write(w http.ResponseWriter, p *Problem) { write(w, p, "") }

func write(w http.ResponseWriter, p *Problem, instance string) {
	body := make(map[string]any, 6+len(p.Ext))
	for k, v := range p.Ext {
		body[k] = v
	}
	body["type"] = "about:blank"
	body["title"] = p.Title
	body["status"] = p.Status
	if p.Detail != "" {
		body["detail"] = p.Detail
	}
	if instance != "" {
		body["instance"] = instance
	}
	if p.Code != "" {
		body["code"] = p.Code
	}
	data, err := json.Marshal(body)
	if err != nil {
		// An unmarshalable extension is a programming error; fall back to a
		// body that cannot fail so the client still gets a problem.
		log.Error("problem body not serializable", "error", err)
		data = []byte(fmt.Sprintf(`{"type":"about:blank","title":%q,"status":%d}`, p.Title, p.Status))
	}
	w.Header().Set("Content-Type", ContentTypeProblem)
	w.WriteHeader(p.Status)
	_, _ = w.Write(append(data, '\n'))
}

// RequestError is StrictHTTPServerOptions.RequestErrorHandlerFunc: the body
// could not be read or decoded.
func RequestError(w http.ResponseWriter, r *http.Request, err error) {
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		write(w, newProblem(http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds %d bytes", tooBig.Limit), r.URL.Path)
		return
	}
	write(w, BadRequest("bad_request", "invalid request: %s", err), r.URL.Path)
}

// ParamError is StdHTTPServerOptions.ErrorHandlerFunc: a path or query
// parameter failed to bind.
func ParamError(w http.ResponseWriter, r *http.Request, err error) {
	write(w, BadRequest("bad_request", "%s", err), r.URL.Path)
}

// ResponseError is StrictHTTPServerOptions.ResponseErrorHandlerFunc. A *Problem
// anywhere in the error chain is rendered as is; any other error is logged
// and answered with a generic 500 so internals never reach the client.
func ResponseError(w http.ResponseWriter, r *http.Request, err error) {
	var p *Problem
	if errors.As(err, &p) {
		write(w, p, r.URL.Path)
		return
	}
	if clientGone(r, err) {
		// Nobody is left to read an answer; this is not a server error.
		log.Debug("client went away", "method", r.Method, "path", r.URL.Path, "error", err)
		return
	}
	log.Error("unhandled handler error", "method", r.Method, "path", r.URL.Path, "error", err)
	write(w, &Problem{Status: http.StatusInternalServerError, Code: "internal", Title: http.StatusText(http.StatusInternalServerError)}, r.URL.Path)
}

// clientGone reports whether err comes from the client disconnecting: the
// request context was canceled, or writing the response hit a closed socket.
func clientGone(r *http.Request, err error) bool {
	return errors.Is(r.Context().Err(), context.Canceled) ||
		errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET)
}

// NotFoundHandler answers unknown /api/ routes with a problem.
var NotFoundHandler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	write(w, NotFound("not_found", "no such route: %s %s", r.Method, r.URL.Path), r.URL.Path)
})
