package httpx

import (
	"log/slog"
	"net/http"
	"time"
)

// Middleware logs one line per finished request: method, path, status and
// duration. Failures log at warn, everything else at debug, so the journal
// keeps the refusals and not the steady traffic of the listeners.
func Middleware(l *slog.Logger) func(http.Handler) http.Handler {
	if l == nil {
		l = log
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			start := time.Now()
			next.ServeHTTP(sr, r)
			level := slog.LevelDebug
			if sr.status >= 400 {
				level = slog.LevelWarn
			}
			l.Log(r.Context(), level, "request", "method", r.Method, "path", r.URL.Path,
				"status", sr.status, "duration_ms", time.Since(start).Milliseconds())
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status, s.wroteHeader = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.wroteHeader = true
	return s.ResponseWriter.Write(b)
}

// Flush keeps per-event flushing of a stream working through the wrapper.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }
