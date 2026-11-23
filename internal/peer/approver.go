package peer

// Approver enrolment. One phone at a time holds the key whose signatures
// decide approval rounds. Root inside the stack mints a one-time code
// (random, 10 minutes, one at a time; `peer-hub approver code`) and shows
// it as a hemma://homelab link; the phone posts its public key with that
// code to the enrolment listener (EnrolURL). The key is stored in meta,
// replacing any earlier phone, and every parked request moves to a new
// round prompted for the new phone.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// EnrolCodeTTL is how long an enrolment code is accepted.
const EnrolCodeTTL = 10 * time.Minute

// ApproverPath is the enrolment route on the enrolment listener.
const ApproverPath = "/api/peer/approvers"

const maxApproverName = 64

// Enrolment errors; http.go maps them to problems with fixed details.
var (
	ErrInvalidCode = errors.New("peer: the enrolment code is wrong, used or expired")
	ErrInvalidKey  = errors.New("peer: the public key or key id does not check out")
)

// Approver is the enrolled phone. PublicKey is the unpadded base64url SPKI
// DER of its P-256 key; KeyID the lowercase hex SHA-256 of that DER.
type Approver struct {
	KeyID      string    `json:"key_id"`
	PublicKey  string    `json:"public_key"`
	Name       string    `json:"name"`
	EnrolledAt time.Time `json:"enrolled_at"`
}

// ApproverCode is a minted enrolment code and the link that carries it.
type ApproverCode struct {
	Code      string
	Link      string
	ExpiresAt time.Time
}

// EnrolIn is a phone's enrolment.
type EnrolIn struct {
	Code, PublicKey, KeyID, Name string
}

// enrolCode is the current code; minting replaces it, a successful
// enrolment consumes it.
type enrolCode struct {
	mu      sync.Mutex
	code    string
	expires time.Time
}

// MintApproverCode replaces any unused code with a fresh one.
func (s *Service) MintApproverCode() ApproverCode {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand does not fail on Linux
	}
	code := base64.RawURLEncoding.EncodeToString(b[:])
	expires := s.now().Add(EnrolCodeTTL)
	s.enrol.mu.Lock()
	s.enrol.code, s.enrol.expires = code, expires
	s.enrol.mu.Unlock()
	return ApproverCode{
		Code:      code,
		Link:      "hemma://homelab?u=" + url.QueryEscape(s.cfg.EnrolURL) + "&c=" + url.QueryEscape(code),
		ExpiresAt: expires,
	}
}

// Approver returns the enrolled phone, if any.
func (s *Service) Approver(ctx context.Context) (Approver, bool, error) {
	return s.st.Approver(ctx)
}

// EnrolApprover checks the code and the key and stores the phone as the
// approver, replacing any earlier one. The code is used up only by a
// successful enrolment.
func (s *Service) EnrolApprover(ctx context.Context, in EnrolIn) (Approver, error) {
	var parked []Request
	defer func() { s.rerounded(ctx, parked) }() // once the lock is released
	s.enrol.mu.Lock()
	defer s.enrol.mu.Unlock()
	now := s.now()
	if s.enrol.code == "" || !now.Before(s.enrol.expires) ||
		subtle.ConstantTimeCompare([]byte(in.Code), []byte(s.enrol.code)) != 1 {
		return Approver{}, ErrInvalidCode
	}
	if n := utf8.RuneCountInString(in.Name); n == 0 || n > maxApproverName || strings.TrimSpace(in.Name) == "" {
		return Approver{}, invalid("name must be 1 to 64 characters")
	}
	if err := checkApproverKey(in.PublicKey, in.KeyID); err != nil {
		return Approver{}, err
	}
	a := Approver{KeyID: in.KeyID, PublicKey: in.PublicKey, Name: in.Name, EnrolledAt: now.UTC()}
	var err error
	if parked, err = s.st.SetApprover(ctx, &a, now); err != nil {
		return Approver{}, err
	}
	s.enrol.code, s.enrol.expires = "", time.Time{}
	s.log.Info("peer approver enrolled", "key_id", a.KeyID, "name", a.Name)
	if s.cfg.OnEnrolled != nil {
		s.cfg.OnEnrolled(a.Name)
	}
	return a, nil
}

// RevokeApprover removes the enrolled phone; decisions are refused until a
// phone enrols again.
func (s *Service) RevokeApprover(ctx context.Context) error {
	parked, err := s.st.SetApprover(ctx, nil, s.now())
	if err != nil {
		return err
	}
	s.log.Info("peer approver revoked")
	s.rerounded(ctx, parked)
	return nil
}

// rerounded follows an approver change that moved the parked requests to a
// new round: each old round's prompt, signed for by the old phone, is
// withdrawn (best effort), and the sweep prompts the new round for the
// phone enrolled then, if any.
func (s *Service) rerounded(ctx context.Context, parked []Request) {
	for _, r := range parked {
		s.withdraw(ctx, r)
		s.changed(r.ID)
	}
}

// checkApproverKey accepts only an unpadded base64url SPKI DER of an ECDSA
// P-256 public key whose lowercase hex SHA-256 is keyID.
func checkApproverKey(publicKey, keyID string) error {
	if publicKey == "" || strings.ContainsAny(publicKey, "=+/") {
		return ErrInvalidKey
	}
	der, err := base64.RawURLEncoding.Strict().DecodeString(publicKey)
	if err != nil {
		return ErrInvalidKey
	}
	sum := sha256.Sum256(der)
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(keyID)) != 1 {
		return ErrInvalidKey
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return ErrInvalidKey
	}
	if k, ok := pub.(*ecdsa.PublicKey); !ok || k.Curve != elliptic.P256() {
		return ErrInvalidKey
	}
	return nil
}
