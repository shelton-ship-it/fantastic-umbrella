// Package linkrec reconhece determinísticamente origens de download através
// de adaptadores registados. Começa sem IA: regras e padrões de URL. Se um
// dia modelos locais acrescentarem valor comprovado por testes, entram aqui
// atrás do mesmo contrato — nunca envio de URLs/histórico para serviços remotos.
package linkrec

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"streamvault/core/domain"
)

// Adapter declara capacidades REAIS de uma família de origens.
type Adapter interface {
	Name() string
	Version() string
	Schemes() []string            // ex.: ["https"], ["magnet"]
	CanRecognize(raw string) bool // reconhecimento sintático, sem rede
	// Parse devolve a fonte normalizada OU erro ErrUnsupported com explicação.
	Parse(raw string) (domain.DownloadSource, error)
	Restrictions() []string // limitações honestas comunicadas ao utilizador
}

// Registry mantém adaptadores ordenados por prioridade explícita.
type Registry struct {
	adapters []Adapter
}

func NewRegistry() *Registry { return &Registry{} }

func (r *Registry) Register(a Adapter) { r.adapters = append(r.adapters, a) }

// Recognize percorre os adaptadores e devolve a primeira origem reconhecida.
// Se NENHUM reconhecer, devolve unsupported com lista do que é suportado —
// o produto explica a limitação em vez de improvisar um extrator universal.
func (r *Registry) Recognize(raw string) (domain.DownloadSource, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return domain.DownloadSource{}, fmt.Errorf("linkrec: entrada vazia")
	}
	for _, a := range r.adapters {
		if a.CanRecognize(raw) {
			return a.Parse(raw)
		}
	}
	var names []string
	for _, a := range r.adapters {
		names = append(names, strings.Join(a.Schemes(), ","))
	}
	sort.Strings(names)
	return domain.DownloadSource{}, domain.NewError(domain.ErrUnsupportedSource, nil,
		fmt.Sprintf("origem não reconhecida; esquemas suportados: %s", strings.Join(names, " | ")),
		"Verifique se o link está completo ou use um adaptador específico.",
		domain.CertaintyHeuristic, false)
}

// ---------- Adaptador HTTP/HTTPS ----------

type httpAdapter struct{}

func NewHTTPAdapter() Adapter { return httpAdapter{} }

func (httpAdapter) Name() string      { return "http-direct" }
func (httpAdapter) Version() string   { return "1.0.0" }
func (httpAdapter) Schemes() []string { return []string{"http", "https"} }
func (httpAdapter) Restrictions() []string {
	return []string{
		"Não contorna DRM, paywalls nem autenticação de terceiros.",
		"A retoma depende do suporte Range do servidor remoto.",
	}
}
func (httpAdapter) CanRecognize(raw string) bool {
	return strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://")
}
func (httpAdapter) Parse(raw string) (domain.DownloadSource, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return domain.DownloadSource{}, domain.NewError(domain.ErrInvalidInput, err,
			"URL http(s) malformada", "Cole o link completo copiado do navegador.",
			domain.CertaintyHeuristic, false)
	}
	name := strings.TrimSuffix(u.Path[strings.LastIndex(u.Path, "/")+1:], ".torrent")
	if name == "" {
		name = u.Host
	}
	return domain.DownloadSource{
		Kind: domain.SourceHTTP, URL: raw, DisplayName: name,
		Metadata: map[string]string{"scheme": u.Scheme},
	}, nil
}

// ---------- Adaptador magnet ----------

var btihRe = regexp.MustCompile(`(?i)^([0-9a-f]{40}|[0-9a-z]{32})$`) // hex160 ou base32

type magnetAdapter struct{}

func NewMagnetAdapter() Adapter { return magnetAdapter{} }

func (magnetAdapter) Name() string      { return "magnet" }
func (magnetAdapter) Version() string   { return "1.0.0" }
func (magnetAdapter) Schemes() []string { return []string{"magnet"} }
func (magnetAdapter) Restrictions() []string {
	return []string{
		"Nome/tamanho só são exibidos quando os metadados forem realmente obtidos.",
		"Depende de peers/DHT disponíveis na rede BitTorrent.",
	}
}
func (magnetAdapter) CanRecognize(raw string) bool {
	return strings.HasPrefix(strings.ToLower(raw), "magnet:?")
}
func (magnetAdapter) Parse(raw string) (domain.DownloadSource, error) {
	qIdx := strings.Index(raw, "?")
	if qIdx < 0 {
		return domain.DownloadSource{}, magnetBad("sem query string")
	}
	values, err := url.ParseQuery(raw[qIdx+1:])
	if err != nil {
		return domain.DownloadSource{}, magnetBad("query string inválida")
	}
	xts := values["xt"]
	var hash string
	for _, xt := range xts {
		if strings.HasPrefix(strings.ToLower(xt), "urn:btih:") {
			h := xt[len("urn:btih:"):]
			if !btihRe.MatchString(h) {
				return domain.DownloadSource{}, magnetBad("info-hash com formato inválido")
			}
			hash = strings.ToLower(h)
			break
		}
	}
	if hash == "" {
		return domain.DownloadSource{}, magnetBad("sem parâmetro xt=urn:btih")
	}
	name := values.Get("dn")
	if name == "" {
		name = shortDisplay(hash)
	}
	tr := map[string]string{}
	if v := values.Get("tr"); v != "" {
		tr["tracker_count"] = fmt.Sprint(len(values["tr"]))
	}
	return domain.DownloadSource{
		Kind: domain.SourceMagnet, URL: raw, InfoHash: hash,
		DisplayName: sanitizeName(name), Metadata: tr,
	}, nil
}

func magnetBad(why string) error {
	return domain.NewError(domain.ErrInvalidInput, nil,
		"magnet link inválido: "+why,
		"Confirme se copiou o link magnet completo.", domain.CertaintyHeuristic, false)
}

func shortDisplay(h string) string {
	if len(h) > 12 {
		return h[:12] + "…"
	}
	return h
}

// sanitizeName remove separadores de caminho — nomes apresentados nunca podem
// sugerir path traversal (defesa em profundidade; security revalida).
func sanitizeName(n string) string {
	n = strings.NewReplacer("/", "-", "\\", "-", "..", "-", "\x00", "").Replace(n)
	n = strings.TrimSpace(n)
	if n == "" {
		return "sem-nome"
	}
	if len(n) > 200 {
		n = n[:200]
	}
	return n
}

// ---------- Adaptador .torrent (caminho local ou URL) ----------

type torrentFileAdapter struct{}

func NewTorrentFileAdapter() Adapter { return torrentFileAdapter{} }

func (torrentFileAdapter) Name() string      { return "torrent-file" }
func (torrentFileAdapter) Version() string   { return "1.0.0" }
func (torrentFileAdapter) Schemes() []string { return []string{"file", "http-torrent"} }
func (torrentFileAdapter) Restrictions() []string {
	return []string{"O ficheiro .torrent deve existir localmente ou ser obtido por HTTPS."}
}
func (torrentFileAdapter) CanRecognize(raw string) bool {
	l := strings.ToLower(raw)
	return strings.HasPrefix(l, "file://") || strings.HasSuffix(l, ".torrent")
}
func (torrentFileAdapter) Parse(raw string) (domain.DownloadSource, error) {
	name := raw
	if strings.HasPrefix(strings.ToLower(raw), "file://") {
		u, err := url.Parse(raw)
		if err != nil {
			return domain.DownloadSource{}, domain.NewError(domain.ErrInvalidInput, err,
				"URL file:// malformada", "Selecione o ficheiro pela janela de ficheiros.",
				domain.CertaintyHeuristic, false)
		}
		name = u.Path
	}
	base := name[strings.LastIndexAny(name, `/\`)+1:]
	return domain.DownloadSource{
		Kind: domain.SourceTorrent, URL: raw, DisplayName: sanitizeName(base),
		Metadata: map[string]string{"needs_open": "true"},
	}, nil
}
