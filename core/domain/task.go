package domain

import (
	"fmt"
	"net/url"
	"time"
)

// SourceKind é o tipo determinístico de origem reconhecida pelo linkrec.
type SourceKind string

const (
	SourceHTTP    SourceKind = "http"    // URL http/https direto
	SourceMagnet  SourceKind = "magnet"  // magnet link BitTorrent
	SourceTorrent SourceKind = "torrent" // ficheiro .torrent local ou URL
	SourceUnknown SourceKind = ""
)

// DownloadSource descreve ONDE obter o conteúdo e as capacidades conhecidas.
type DownloadSource struct {
	Kind        SourceKind
	URL         string            // http(s) ou magnet (nunca contém segredos em logs — usar Redacted)
	InfoHash    string            // hex lowercase, quando conhecido
	DisplayName string            // nome apresentado ao utilizador (validado contra traversal)
	Metadata    map[string]string // extensões do adaptador
}

// Redacted devolve uma versão segura para exibição/logs: query strings são
// truncadas porque podem conter tokens assinados (URLs expirados).
func (s DownloadSource) Redacted() string {
	if s.Kind == SourceMagnet {
		return fmt.Sprintf("magnet:?xt=urn:btih:%s&dn=%s", shortHash(s.InfoHash), s.DisplayName)
	}
	u, err := url.Parse(s.URL)
	if err != nil || u.Host == "" {
		return "<url-inválida>"
	}
	q := ""
	if u.RawQuery != "" {
		q = "?…(omitido)"
	}
	return u.Scheme + "://" + u.Host + u.Path + q
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// FileMetadata é a descrição de UM ficheiro dentro de uma tarefa
// (um torrent pode conter muitos; HTTP tem tipicamente um).
type FileMetadata struct {
	Index       int    // índice estável dentro da tarefa
	Path        string // caminho RELATIVO validado (nunca absoluto, nunca ..)
	SizeBytes   int64
	ContentType string
	SHA256Hex   string // quando fornecido pela origem ou calculado localmente
	Selected    bool   // seleção parcial de ficheiros (BitTorrent)
}

// IntegrityRequirement define o que a política exige antes de Completed.
type IntegrityRequirement int

const (
	IntegrityNone          IntegrityRequirement = iota // sem verificação exigida
	IntegrityRemoteETag                                // validar ETag/tamanho remoto no finalize
	IntegritySHA256                                    // hash integral obrigatório
	IntegrityTorrentPieces                             // verificação por peças BitTorrent
)

// DownloadPolicy agrupa regras aplicadas a uma tarefa pelo orquestrador.
type DownloadPolicy struct {
	MaxSizeBytes     int64
	RequireIntegrity IntegrityRequirement
	AllowResume      bool
	MaxConcurrency   int
	SpeedLimitBps    int64 // 0 = sem limite
	DestinationDir   string
	Category         string
}

// ProgressSnapshot é imutável e transporta progresso para eventos/UI.
type ProgressSnapshot struct {
	TaskID     string
	State      State
	BytesDone  int64
	BytesTotal int64 // -1 se desconhecido
	SpeedBps   float64
	FilesDone  int
	FilesTotal int
	UpdatedAt  time.Time
}

// Fraction devolve [0,1] ou -1 se total desconhecido.
func (p ProgressSnapshot) Fraction() float64 {
	if p.BytesTotal <= 0 {
		return -1
	}
	f := float64(p.BytesDone) / float64(p.BytesTotal)
	if f > 1 {
		return 1
	}
	return f
}

// LicenseStatusResumo evita dependência circular: o orquestrador só precisa
// de saber se direitos especiais estão ativos, não do pacote license completo.
type Entitlements struct {
	AdFree          bool
	PriorityQueue   bool
	AdvancedFilters bool
	TorrentEngine   bool
	LANTransfer     bool
}

// DownloadTask é a unidade fundamental gerida pelo orquestrador e persistida.
type DownloadTask struct {
	ID           string
	Source       DownloadSource
	Policy       DownloadPolicy
	State        State
	Progress     ProgressSnapshot
	Error        *DownloadError
	Files        []FileMetadata
	CreatedAt    time.Time
	UpdatedAt    time.Time
	Priority     int // maior = mais prioritário
	Entitlements Entitlements
	Version      int64 // optimistic concurrency na persistência
}

// Transition aplica uma transição de estado VALIDADA, atualizando UpdatedAt.
// Retorna erro descritivo se a máquina de estados a recusar — ex.: nunca
// Running->Completed diretamente quando a política exige Verifying.
func (t *DownloadTask) Transition(next State) error {
	if t.Policy.RequireIntegrity != IntegrityNone && next == StateCompleted && t.State != StateVerifying {
		return fmt.Errorf("domain: tarefa %s exige verificação (nível %d) antes de completed; transição direta recusada",
			t.ID, int(t.Policy.RequireIntegrity))
	}
	if err := ValidateTransition(t.State, next); err != nil {
		return err
	}
	t.State = next
	t.UpdatedAt = time.Now().UTC()
	return nil
}

// FailRegister marca falha terminal com diagnóstico completo.
func (t *DownloadTask) FailRegister(err *DownloadError) error {
	if err == nil {
		return fmt.Errorf("domain: fail requer erro não-nulo")
	}
	if err := ValidateTransition(t.State, StateFailed); err != nil {
		return err
	}
	t.Error = err
	t.State = StateFailed
	t.UpdatedAt = time.Now().UTC()
	return nil
}
