// Package orchestrator coordena motores através das interfaces engine.Engine.
// A fila NÃO conhece HTTP nem BitTorrent — apenas contratos. Isto satisfaz o
// requisito "substituir motor sem reescrever fila/licenciamento/UI".
package orchestrator

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"streamvault/core/diag"
	"streamvault/core/domain"
	"streamvault/core/engine"
)

// Store persiste tarefas (implementado em storage/ na Fase 4; interface aqui
// para manter o orquestrador testável sem disco).
type Store interface {
	Save(t *domain.DownloadTask) error
	Get(id string) (*domain.DownloadTask, error)
	List() ([]*domain.DownloadTask, error)
	Delete(id string) error
}

// EngineRouter escolhe o motor para cada origem via CanHandle.
type EngineRouter struct {
	mu     sync.RWMutex
	engine map[domain.SourceKind]engine.Engine
}

func NewEngineRouter() *EngineRouter {
	return &EngineRouter{engine: map[domain.SourceKind]engine.Engine{}}
}

func (r *EngineRouter) Register(kind domain.SourceKind, e engine.Engine) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.engine[kind] = e
}

func (r *EngineRouter) For(src domain.DownloadSource) (engine.Engine, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.engine[src.Kind]
	if !ok || !e.CanHandle(src) {
		return nil, domain.NewError(domain.ErrUnsupportedSource, nil,
			fmt.Sprintf("nenhum motor registrado trata origem %q", src.Kind),
			"Atualize a aplicação ou use uma origem suportada.", domain.CertaintyObserved, false)
	}
	return e, nil
}

// Orchestrator é o coração da fila: prioridades, concorrência, controlo.
type Orchestrator struct {
	mu      sync.Mutex
	store   Store
	router  *EngineRouter
	sink    engine.EventSink
	handles map[string]engine.JobHandle
	maxConc int
	running int
	ctx     context.Context
	cancel  context.CancelFunc
	clock   func() time.Time
}

type Options struct {
	Store     Store
	Router    *EngineRouter
	Sink      engine.EventSink
	MaxConcur int
	Clock     func() time.Time // injetável p/ testes
}

func New(o Options) (*Orchestrator, error) {
	if o.Store == nil || o.Router == nil {
		return nil, fmt.Errorf("orchestrator: Store e Router obrigatórios")
	}
	if o.MaxConcur <= 0 {
		o.MaxConcur = 3
	}
	ctx, cancel := context.WithCancel(context.Background())
	clock := o.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Orchestrator{
		store: o.Store, router: o.Router, sink: o.Sink,
		maxConc: o.MaxConcur, handles: map[string]engine.JobHandle{},
		ctx: ctx, cancel: cancel, clock: clock,
	}, nil
}

// Submit cria tarefa a partir de origem reconhecida e enfileira.
func (o *Orchestrator) Submit(src domain.DownloadSource, policy domain.DownloadPolicy) (*domain.DownloadTask, error) {
	t := &domain.DownloadTask{
		ID: newTaskID(o.clock()), Source: src, Policy: policy,
		State: domain.StatePending, CreatedAt: o.clock().UTC(), UpdatedAt: o.clock().UTC(),
		Progress: domain.ProgressSnapshot{BytesTotal: -1},
	}
	if err := o.store.Save(t); err != nil {
		return nil, fmt.Errorf("orchestrator: persistir: %w", err)
	}
	return t, nil
}

// StartNext inicia a próxima tarefa elegível (prioridade maior primeiro).
func (o *Orchestrator) StartNext() (*domain.DownloadTask, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.running >= o.maxConc {
		return nil, nil // sem capacidade; chamador agenda retry
	}
	tasks, err := o.store.List()
	if err != nil {
		return nil, err
	}
	var pending []*domain.DownloadTask
	for _, t := range tasks {
		if t.State == domain.StatePending {
			pending = append(pending, t)
		}
	}
	sort.SliceStable(pending, func(i, j int) bool {
		if pending[i].Priority != pending[j].Priority {
			return pending[i].Priority > pending[j].Priority
		}
		return pending[i].CreatedAt.Before(pending[j].CreatedAt)
	})
	if len(pending) == 0 {
		return nil, nil
	}
	t := pending[0]
	eng, err := o.router.For(t.Source)
	if err != nil {
		de := domain.NewError(domain.ErrUnsupportedSource, err, err.Error(),
			"Confirme o link; se a origem é válida mas não suportada, aguarde uma atualização com novos adaptadores.",
			domain.CertaintyObserved, false)
		t.FailRegister(de)
		o.store.Save(t)
		return t, err
	}
	if err := t.Transition(domain.StateRunning); err != nil {
		return nil, err
	}
	h, err := eng.Start(o.ctx, engine.StartRequest{Task: *t, Sink: o.sink})
	if err != nil {
		t.FailRegister(diag.Explain(err, t.Source.Redacted()))
		o.store.Save(t)
		return t, err
	}
	o.handles[t.ID] = h
	o.running++
	o.store.Save(t)
	o.emitState(t)
	return t, nil
}

func (o *Orchestrator) Pause(id string) error  { return o.control(id, "pause") }
func (o *Orchestrator) Resume(id string) error { return o.control(id, "resume") }
func (o *Orchestrator) Cancel(id string) error { return o.control(id, "cancel") }

func (o *Orchestrator) control(id, verb string) error {
	o.mu.Lock()
	h, ok := o.handles[id]
	o.mu.Unlock()
	if !ok {
		return fmt.Errorf("orchestrator: tarefa %s não está ativa", id)
	}
	var err error
	switch verb {
	case "pause":
		err = h.Pause(o.ctx)
	case "resume":
		err = h.Resume(o.ctx)
	case "cancel":
		err = h.Cancel(o.ctx)
	}
	if err != nil {
		return err
	}
	o.mu.Lock()
	if verb == "cancel" {
		delete(o.handles, id)
		if o.running > 0 {
			o.running--
		}
	}
	o.mu.Unlock()
	t, err := o.store.Get(id)
	if err != nil {
		return err
	}
	target := map[string]domain.State{"pause": domain.StatePaused, "resume": domain.StateRunning, "cancel": domain.StateCancelled}[verb]
	if err := t.Transition(target); err != nil {
		return err
	}
	o.store.Save(t)
	o.emitState(t)
	return nil
}

// Recover marca Running->Failed após deteção de encerramento inesperado
// (chamado no arranque com estado carregado do store): nenhuma transferência
// sobreviveu ao processo, logo nada pode continuar "a correr" fantasma.
func (o *Orchestrator) Recover() (int, error) {
	tasks, err := o.store.List()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, t := range tasks {
		if t.State == domain.StateRunning || t.State == domain.StateVerifying {
			t.FailRegister(domain.NewError(domain.ErrConnectionLost, nil,
				"Transferência interrompida por fecho da aplicação.",
				"Pode retomar; o progresso parcial em disco foi preservado.",
				domain.CertaintyHeuristic, true))
			// Failed->Pending é transição válida (retry explícito)
			if err := t.Transition(domain.StatePending); err == nil {
				o.store.Save(t)
				n++
			}
		}
	}
	return n, nil
}

func (o *Orchestrator) emitState(t *domain.DownloadTask) {
	if o.sink == nil {
		return
	}
	o.sink.Emit(engine.Event{
		Kind: engine.EventStateChanged, TaskID: t.ID, State: t.State,
		Progress: t.Progress, Timestamp: o.clock().UnixMilli(),
	})
}

func (o *Orchestrator) Shutdown(ctx context.Context) error {
	o.cancel()
	return nil
}

func newTaskID(now time.Time) string {
	return fmt.Sprintf("dl-%d-%06d", now.UnixNano()%1e15, now.Nanosecond()%1000000)
}
