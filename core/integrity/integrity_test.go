package integrity

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHashAndVerify(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.bin")
	content := make([]byte, 3<<20) // 3 MiB — exercita streaming multi-buffer
	for i := range content {
		content[i] = byte(i % 251)
	}
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := HashFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 64 {
		t.Fatalf("hash sha256 hex esperado, obtive %s", h)
	}
	res, _, err := VerifyFile(p, h)
	if err != nil || res != ResultOK {
		t.Fatalf("verificação honesta falhou: %v %v", res, err)
	}
	res, _, _ = VerifyFile(p, "0000000000000000000000000000000000000000000000000000000000000000")
	if res != ResultMismatch {
		t.Fatal("mismatch deveria ser detetado")
	}
	res, _, _ = VerifyFile(p, "")
	if res != ResultMissingExpected {
		t.Fatal("sem hash esperado NÃO pode afirmar verificado")
	}
}

func TestRemoteIdentityDrift(t *testing.T) {
	old := RemoteIdentity{ETag: `"abc"`, SizeBytes: 100, CapturedAt: time.Now()}
	same := RemoteIdentity{ETag: `"abc"`, SizeBytes: 100}
	if d := old.Compare(same); d != "" {
		t.Fatalf("idêntico não deveria reportar drift: %s", d)
	}
	changed := RemoteIdentity{ETag: `"xyz"`, SizeBytes: 101}
	if d := old.Compare(changed); d == "" {
		t.Fatal("drift de ETag/tamanho não reportado")
	}
}
