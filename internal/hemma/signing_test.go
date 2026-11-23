package hemma

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture is testdata/approval-signing.json, copied verbatim from the Hemma
// repo (fixtures/approval-signing.json) with its .txt sibling.
type fixture struct {
	Request   string `json:"request"`
	Round     int64  `json:"round"`
	Step      string `json:"step"`
	Decision  string `json:"decision"`
	Expires   int64  `json:"expires"`
	PublicKey string `json:"public_key"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

func loadFixture(t *testing.T) (fixture, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "approval-signing.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	txt, err := os.ReadFile(filepath.Join("testdata", "approval-signing.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return f, string(txt)
}

func TestFixtureTextMatchesByteForByte(t *testing.T) {
	t.Parallel()
	f, txt := loadFixture(t)
	if got := SignedText(f.Request, f.Round, f.Step, f.Decision, f.Expires); got != txt {
		t.Fatalf("signed text\n%q\nwant\n%q", got, txt)
	}
}

func TestFixtureKeyID(t *testing.T) {
	t.Parallel()
	f, _ := loadFixture(t)
	der, err := DecodeB64URL(f.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := KeyID(der); got != f.KeyID {
		t.Fatalf("key id = %s, want %s", got, f.KeyID)
	}
	sum := sha256.Sum256(der)
	if hex.EncodeToString(sum[:]) != f.KeyID {
		t.Fatal("KeyID is not the lowercase hex sha256 of the DER")
	}
}

func TestFixtureSignatureVerifies(t *testing.T) {
	t.Parallel()
	f, txt := loadFixture(t)
	if err := Verify(f.PublicKey, txt, f.Signature); err != nil {
		t.Fatalf("fixture signature: %v", err)
	}
}

func TestVerifyRefuses(t *testing.T) {
	t.Parallel()
	f, txt := loadFixture(t)
	flipped := []byte(txt)
	flipped[len(flipped)-1] ^= 1
	std := strings.NewReplacer("-", "+", "_", "/").Replace(f.PublicKey)
	if std == f.PublicKey {
		t.Fatal("fixture key has no base64url-only characters; the standard-base64 case proves nothing")
	}
	sigStd := strings.NewReplacer("-", "+", "_", "/").Replace(f.Signature)
	cases := map[string]struct{ key, text, sig string }{
		"flipped text byte":     {f.PublicKey, string(flipped), f.Signature},
		"other decision":        {f.PublicKey, SignedText(f.Request, f.Round, f.Step, "deny", f.Expires), f.Signature},
		"padded signature":      {f.PublicKey, txt, f.Signature + "=="},
		"padded key":            {f.PublicKey + "=", txt, f.Signature},
		"standard-base64 key":   {std, txt, f.Signature},
		"standard-base64 sig":   {f.PublicKey, txt, sigStd},
		"empty signature":       {f.PublicKey, txt, ""},
		"signature with spaces": {f.PublicKey, txt, " " + f.Signature},
	}
	if sigStd == f.Signature {
		delete(cases, "standard-base64 sig")
	}
	for name, c := range cases {
		if err := Verify(c.key, c.text, c.sig); err == nil {
			t.Errorf("%s: verified, want refused", name)
		}
	}
}

func TestDecodeB64URLIsStrict(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"QQ==", "QQ=", "a+b", "a/b", "QQ\n", "QR"} {
		if _, err := DecodeB64URL(s); err == nil {
			t.Errorf("%q decoded, want refused", s)
		}
	}
	if b, err := DecodeB64URL("QQ"); err != nil || string(b) != "A" {
		t.Fatalf("QQ = %q, %v", b, err)
	}
}
