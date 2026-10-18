// Package engine define os CONTRATOS entre o orquestrador e os motores de
// transferência (HTTP, BitTorrent). Nada aqui depende de UI nem de um motor
// concreto: a fila fala apenas com estas interfaces.
package engine

import (
	"context"

	"streamvault/core/domain"
)

// JobHandle é o controlo assíncrono de uma transferência em curso.
type JobHandle interface {
	TaskID() string
	// Pause interrompe a rede mantendo estado recuperável em disco.
	Pause(ctx context.Context) error
	// Resume retoma a partir do estado persistido mais recente.
	Resume(ctx context.Context) error
	// Cancel aborta definitivamente; implementação deve libertar recursos.
	Cancel(ctx context.Context) error
	// Snapshot devolve o último progresso conhecido (nunca bloqueia).
	Snapshot() domain.ProgressSnapshot
}

// EventKind categoriza eventos emitidos para UI/orquestrador/observabilidade.
type EventKind int

const (
	EventProgress EventKind = iota
	EventStateChanged
	EventFileDiscovered // metadados reais disponíveis (nome/tamanho confirmados)
	EventError
	EventCompleted
	EventIntegrityReport
)

// Event é imutável e seguro para logs: nunca conter URLs completas com query.
type Event struct {
	Kind      EventKind
	TaskID    string
	Progress  domain.ProgressSnapshot
	State     domain.State
	Error     *domain.DownloadError
	Timestamp int64 // unix ms UTC
	Payload   map[string]string
}

// EventSink recebe eventos dos motores. Implementações NÃO podem bloquear o
// caminho de dados — buffering é responsabilidade do consumidor.
type EventSink interface {
	Emit(Event)
}

// Capabilities descreve honestamente o que um motor sabe fazer. O
// orquestrador usa isto para decidir estratégias seguras (ex.: sem Range →
// sem retoma parcial; sem metadados → não prometer nome/tamanho).
type Capabilities struct {
	SupportsPause        bool
	SupportsResume       bool
	SupportsSegmentation bool // GETs paralelos por intervalo
	SupportsMetadata     bool // nome/tamanho antes do primeiro byte?
	SupportsVerify       bool // verificação nativa (peças/hashes)
	NeedsNetwork         bool
	EngineVersion        string
}

// StartRequest contém tudo o que um motor precisa para iniciar uma tarefa.
// O motor NÃO pode mutar Task; trabalha sobre cópias e reporta via eventos.
type StartRequest struct {
	Task domain.DownloadTask
	Sink EventSink
}

// Engine é o contrato único que HTTP e BitTorrent implementam.
// Substituir um motor não toca na fila, no licenciamento nem na UI.
type Engine interface {
	Name() string
	Capabilities() Capabilities
	// CanHandle reporta se este motor reconhece a origem (linkrec decide,
	// mas o motor tem a palavra final sobre suporte real).
	CanHandle(src domain.DownloadSource) bool
	// Start inicia a transferência; devolve handle imediatamente. O trabalho
	// decorre em goroutines internas ligadas ao ctx fornecido.
	Start(ctx context.Context, req StartRequest) (JobHandle, error)
	// Close liberta recursos globais do motor (shutdown ordenado).
	Close() error
}
