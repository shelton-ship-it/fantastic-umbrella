package security

import "testing"

func TestCheckURLBlocksSSRF(t *testing.T) {
	cases := []string{
		"http://127.0.0.1/admin",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.5/share.bin",
		"http://[::1]/x",
	}
	for _, u := range cases {
		fs := CheckURL(u, DefaultOptions())
		if len(fs) == 0 || fs[0].Severity != "block" {
			t.Errorf("SSRF não bloqueado: %s -> %v", u, fs)
		}
	}
}

func TestCheckURLOkForPublic(t *testing.T) {
	fs := CheckURL("https://cdn.example.com/a.zip", DefaultOptions())
	for _, f := range fs {
		if f.Severity == "block" {
			t.Errorf("URL pública bloqueada indevidamente: %v", f)
		}
	}
}

func TestDangerousSchemesBlocked(t *testing.T) {
	for _, u := range []string{"javascript:alert(1)", "data:text/html,<script>", "file:///etc/passwd"} {
		fs := CheckURL(u, DefaultOptions())
		if len(fs) == 0 || fs[0].Severity != "block" {
			t.Errorf("esquema perigoso não bloqueado: %s", u)
		}
	}
}

func TestFileNameTraversal(t *testing.T) {
	if _, fs := CheckFileName("../../windows/system32/evil.exe"); !hasBlockCode(fs, "path_traversal") {
		t.Errorf("traversal não detetado: %v", fs)
	}
	if clean, fs := CheckFileName("videos/filme.mp4"); len(fs) != 0 || clean != "videos/filme.mp4" {
		t.Errorf("caminho legítimo rejeitado: %s %v", clean, fs)
	}
	if _, fs := CheckFileName("installer.exe"); len(fs) == 0 || fs[0].Code != "dangerous_extension" {
		t.Errorf("extensão perigosa sem aviso: %v", fs)
	}
	if _, fs := CheckFileName("C:\\Windows\\evil.dll"); len(fs) == 0 || fs[0].Code != "absolute_path" {
		t.Errorf("caminho absoluto windows não bloqueado: %v", fs)
	}
}

func hasBlockCode(fs []Finding, code string) bool {
	for _, f := range fs {
		if f.Code == code && f.Severity == "block" {
			return true
		}
	}
	return false
}
