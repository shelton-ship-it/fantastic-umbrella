package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

func newTestLicense(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey) *License {
	t.Helper()
	l := &License{
		FormatVersion: FormatVersion, LicenseID: "lic-001", ProductID: "streamvault-windows",
		Edition: "pro", IssuedAt: time.Now().UTC().Add(-time.Hour).Unix(),
		Entitlements:     Entitlements{AdFree: true, TorrentEngine: true},
		ActivationPolicy: ActivationPolicy{MaxDevices: 3},
		KeyID:            "key-2026-01",
	}
	if err := l.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return l
}

func setup(t *testing.T) (*Validator, ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ring := NewKeyring()
	if err := ring.Trust("key-2026-01", pub); err != nil {
		t.Fatal(err)
	}
	v := &Validator{ProductID: "streamvault-windows", Ring: ring}
	return v, pub, priv
}

func TestValidLicense(t *testing.T) {
	v, pub, priv := setup(t)
	res := v.Validate(newTestLicense(t, pub, priv))
	if res.Status != StatusValid || !res.Permanent || !res.Entitlements.AdFree {
		t.Fatalf("esperava válida/permanente/adfree, obtive %+v", res)
	}
}

func TestTamperedSignature(t *testing.T) {
	v, pub, priv := setup(t)
	l := newTestLicense(t, pub, priv)
	l.Edition = "enterprise" // adulteração após assinatura
	res := v.Validate(l)
	if res.Status != StatusInvalidSignature {
		t.Fatalf("assinatura adulterada deveria falhar, obtive %v (%s)", res.Status, res.Reason)
	}
}

func TestUnknownKey(t *testing.T) {
	v, _, _ := setup(t)
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	l := newTestLicense(t, otherPub, otherPriv)
	l.KeyID = "key-maliciosa"
	if res := v.Validate(l); res.Status != StatusUnknownKey {
		t.Fatalf("chave desconhecida deveria falhar, obtive %v", res.Status)
	}
}

func TestWrongProduct(t *testing.T) {
	v, pub, priv := setup(t)
	l := newTestLicense(t, pub, priv)
	l.ProductID = "outro-produto"
	l.Signature = ""
	if err := l.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if res := v.Validate(l); res.Status != StatusWrongProduct {
		t.Fatalf("produto errado deveria falhar, obtive %v", res.Status)
	}
}

func TestExpiredAndPermanent(t *testing.T) {
	v, pub, priv := setup(t)
	l := newTestLicense(t, pub, priv)
	l.ExpiresAt = time.Now().UTC().Add(-time.Minute).Unix()
	l.Signature = ""
	l.Sign(priv)
	if res := v.Validate(l); res.Status != StatusExpired {
		t.Fatalf("licença expirada deveria falhar, obtive %v", res.Status)
	}
}

func TestNotYetValid(t *testing.T) {
	v, pub, priv := setup(t)
	l := newTestLicense(t, pub, priv)
	l.NotBefore = time.Now().UTC().Add(48 * time.Hour).Unix()
	l.Signature = ""
	l.Sign(priv)
	if res := v.Validate(l); res.Status != StatusNotYetValid {
		t.Fatalf("not_before futuro deveria falhar, obtive %v", res.Status)
	}
}

func TestClockSkewDetection(t *testing.T) {
	v, pub, priv := setup(t)
	l := newTestLicense(t, pub, priv)
	v.Now = func() time.Time { return time.Unix(l.IssuedAt, 0).Add(-72 * time.Hour) }
	if res := v.Validate(l); res.Status != StatusClockSkew {
		t.Fatalf("relógio retrocedido 72h deveria dar clock_skew, obtive %v", res.Status)
	}
}

func TestMissingField(t *testing.T) {
	v, pub, priv := setup(t)
	l := newTestLicense(t, pub, priv)
	l.LicenseID = ""
	if res := v.Validate(l); res.Status != StatusMalformed {
		t.Fatalf("campo obrigatório em falta deveria dar malformed, obtive %v", res.Status)
	}
}

func TestUnknownFormat(t *testing.T) {
	v, pub, priv := setup(t)
	l := newTestLicense(t, pub, priv)
	l.FormatVersion = 99
	l.Signature = ""
	l.Sign(priv)
	if res := v.Validate(l); res.Status != StatusUnknownFormat {
		t.Fatalf("format_version 99 deveria dar unknown_format, obtive %v", res.Status)
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	data, _ := json.Marshal(map[string]interface{}{
		"format_version": 1, "extra_malicioso": true,
	})
	if _, err := Parse(data); err == nil {
		t.Fatal("Parse deveria recusar campos desconhecidos (formato estrito)")
	}
}

func TestKeyRotation(t *testing.T) {
	pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	ring := NewKeyring()
	ring.Trust("key-old", pub1)
	ring.Trust("key-new", pub2)
	v := &Validator{ProductID: "streamvault-windows", Ring: ring}
	l := &License{FormatVersion: FormatVersion, LicenseID: "x", ProductID: "streamvault-windows",
		Edition: "pro", IssuedAt: time.Now().UTC().Add(-time.Hour).Unix(), KeyID: "key-old"}
	l.Sign(priv1)
	if res := v.Validate(l); res.Status != StatusValid {
		t.Fatalf("licença antiga deve continuar válida durante rotação, obtive %v", res.Status)
	}
}
