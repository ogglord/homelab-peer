package web

import (
	"fmt"
	"html/template"
	"strings"
	"time"

	"rsc.io/qr"
)

// qrSVG draws text as a QR code (ECC M) with the 4-module quiet zone QR
// readers expect. Only numbers reach the markup.
func qrSVG(text string) (template.HTML, error) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	const border = 4
	var path strings.Builder
	for y := range c.Size {
		for x := range c.Size {
			if c.Black(x, y) {
				fmt.Fprintf(&path, "M%d %dh1v1h-1z", x+border, y+border)
			}
		}
	}
	n := c.Size + 2*border
	return template.HTML(fmt.Sprintf(
		`<svg class="qr" role="img" aria-label="Enrolment QR code" viewBox="0 0 %d %d" shape-rendering="crispEdges"><rect width="%d" height="%d" fill="#fff"/><path d="%s" fill="#000"/></svg>`,
		n, n, n, n, path.String())), nil
}

// ago is a time as "4m ago".
func (s *server) ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := s.now().Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

// stamp is a time as "15:04" today, else "2 Jan 15:04".
func (s *server) stamp(t time.Time) string {
	t, now := t.Local(), s.now().Local()
	if t.YearDay() == now.YearDay() && t.Year() == now.Year() {
		return t.Format("15:04")
	}
	if t.Year() == now.Year() {
		return t.Format("2 Jan 15:04")
	}
	return t.Format("2 Jan 2006")
}

// full is a time for a title attribute.
func full(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format("Mon 2 Jan 2006 15:04:05 MST")
}

// short is the first n characters of an id or key.
func short(n int, s string) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
