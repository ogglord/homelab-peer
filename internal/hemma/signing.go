package hemma

// The approval signature (docs/homelab.md in the Hemma repo, "The signed
// text"): the enrolled phone signs a fixed text naming one request round and
// its decision with its P-256 key; the homelab rebuilds that text from the
// decision's own fields and verifies the signature against the key it
// enrolled itself, never against a key a prompt or the hub names.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// Decisions a phone signs.
const (
	DecisionApprove = "approve"
	DecisionDeny    = "deny"
)

// ErrBadSignature is Verify's refusal: the key, the signature or the text
// does not check out.
var ErrBadSignature = errors.New("hemma: the signature does not verify")

// SignedText is the exact text a phone signs for decision ("approve" or
// "deny") on round of request, whose park has fingerprint and whose prompt
// expires at the unix second expires. Lines are joined by \n with none
// after the last.
func SignedText(request string, round int64, fingerprint, decision string, expires int64) string {
	return strings.Join([]string{
		"hemma-approval-v1",
		"request=" + request,
		"round=" + strconv.FormatInt(round, 10),
		"step=" + fingerprint,
		"decision=" + decision,
		"expires=" + strconv.FormatInt(expires, 10),
	}, "\n")
}

// DecodeB64URL decodes unpadded base64url strictly: only [A-Za-z0-9_-], no
// padding, no whitespace (Go's decoder skips \r and \n on its own), and no
// stray bits.
func DecodeB64URL(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return nil, errors.New("hemma: not unpadded base64url")
		}
	}
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

// KeyID is a key's id: the lowercase hex SHA-256 of its SPKI DER bytes.
func KeyID(spkiDER []byte) string {
	sum := sha256.Sum256(spkiDER)
	return hex.EncodeToString(sum[:])
}

// Verify checks that signature (ASN.1 DER ECDSA, unpadded base64url) signs
// text with SHA-256 under publicKey (P-256 SPKI DER, unpadded base64url).
func Verify(publicKey, text, signature string) error {
	der, err := DecodeB64URL(publicKey)
	if err != nil || len(der) == 0 {
		return ErrBadSignature
	}
	sig, err := DecodeB64URL(signature)
	if err != nil || len(sig) == 0 {
		return ErrBadSignature
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return ErrBadSignature
	}
	k, ok := pub.(*ecdsa.PublicKey)
	if !ok || k.Curve != elliptic.P256() {
		return ErrBadSignature
	}
	sum := sha256.Sum256([]byte(text))
	if !ecdsa.VerifyASN1(k, sum[:], sig) {
		return ErrBadSignature
	}
	return nil
}
