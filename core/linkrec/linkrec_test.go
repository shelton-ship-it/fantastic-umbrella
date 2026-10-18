package linkrec

import (
	"testing"

	"streamvault/core/domain"
)

func defaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(NewHTTPAdapter())
	r.Register(NewMagnetAdapter())
	r.Register(NewTorrentFileAdapter())
	return r
}

func TestRecognizeHTTPS(t *testing.T) {
	src, err := defaultRegistry().Recognize("https://cdn.example.com/videos/movie.mp4?token=xyz")
	if err != nil {
		t.Fatal(err)
	}
	if src.Kind != domain.SourceHTTP || src.DisplayName != "movie.mp4" {
		t.Fatalf(" %+v", src)
	}
}

func TestRecognizeMagnetHexAndBase32(t *testing.T) {
	hex40 := "0123456789abcdef0123456789abcdef01234567"
	src, err := defaultRegistry().Recognize("magnet:?xt=urn:btih:" + hex40 + "&dn=Filme%20Completo&tr=http%3A%2F%2Ftracker.local")
	if err != nil {
		t.Fatal(err)
	}
	if src.InfoHash != hex40 || src.Kind != domain.SourceMagnet {
		t.Fatalf("%+v", src)
	}
	if src.Metadata["tracker_count"] != "1" {
		t.Errorf("trackers não contados: %v", src.Metadata)
	}
	b32 := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	src2, err := defaultRegistry().Recognize("magnet:?xt=urn:btih:" + b32)
	if err != nil || src2.InfoHash != "abcdefghijklmnopqrstuvwxyz234567" {
		t.Fatalf("base32 deveria ser aceite: %v %+v", err, src2)
	}
}

func TestMagnetInvalidHashRejected(t *testing.T) {
	_, err := defaultRegistry().Recognize("magnet:?xt=urn:btih:ZZZZ&dn=x")
	if err == nil {
		t.Fatal("info-hash inválido deve ser recusado")
	}
	if !domain.IsClass(err, domain.ErrInvalidInput) {
		t.Fatalf("erro tipado esperado invalid_input, obtive %v", err)
	}
}

func TestUnsupportedExplainsLimitation(t *testing.T) {
	_, err := defaultRegistry().Recognize("ftp://example.com/file.iso")
	de, ok := err.(*domain.DownloadError)
	if !ok || de.Class != domain.ErrUnsupportedSource {
		t.Fatalf("deveria devolver unsupported_source com explicação, obtive %v", err)
	}
	if de.Action == "" {
		t.Error("diagnóstico sem ação recomendada")
	}
}

func TestMagnetNameTraversalNeutralized(t *testing.T) {
	src, err := defaultRegistry().Recognize("magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=../../etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	if src.DisplayName == "../../etc/passwd" {
		t.Fatal("nome com traversal deveria ser neutralizado na apresentação")
	}
}
