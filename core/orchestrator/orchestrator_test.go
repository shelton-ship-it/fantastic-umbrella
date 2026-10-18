package orchestrator

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"streamvault/core/domain"
	"streamvault/core/engine"
)

// memStore — Store em memória para testes determinísticos.
type memStore struct {
	mu    sync.Mutex
	tasks map[string]*domain.DownloadTask
	order []string
}

func newMemStore() *memStore { return &memStore{tasks: map[string]*domain.DownloadTask{}} }

func (m *memStore) Save(t *domain.DownloadTask) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *t
	if _, exists := m.tasks[t.ID]; !exists {
		m.order = append(m.order, t.ID)
	}
	m.tasks[t.ID] = &c
	return nil
}
func (m *memStore) Get(id string) (*domain.DownloadTask, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tasks[id]
	if !ok {
		return nil, fmt.Errorf("não encontrada: %s", id)
	}
	c := *t
	return &c, nil
}
func (m *memStore) List() ([]*domain.DownloadTask, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*domain.DownloadTask
	for _, id := range m.order {
		c := *m.tasks[id]
		out = append(out, &c)
	}
	return out, nil
}
func (m *memStore) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tasks, id)
	return nil
}

// fakeEngine implementa engine.Engine sem rede nem UI.
type fakeEngine struct {
	failStart bool
	handles   []*fakeHandle
}

type fakeHandle struct {
	id     string
	closed bool
}

func (h *fakeHandle) TaskID() string                   { return h.id }
func (h *fakeHandle) Pause(ctx context.Context) error  { return nil }
func (h *fakeHandle) Resume(ctx context.Context) error { return nil }
func (h *fakeHandle) Cancel(ctx context.Context) error { h.closed = true; return nil }
func (h *fakeHandle) Snapshot() domain.ProgressSnapshot {
	return domain.ProgressSnapshot{TaskID: h.id, State: domain.StateRunning}
}

func (e *fakeEngine) Name() string { return "fake-http" }
func (e *fakeEngine) Capabilities() engine.Capabilities {
	return engine.Capabilities{SupportsPause: true, SupportsResume: true}
}
func (e *fakeEngine) CanHandle(src domain.DownloadSource) bool { return src.Kind == domain.SourceHTTP }
func (e *fakeEngine) Start(ctx context.Context, req engine.StartRequest) (engine.JobHandle, error) {
	if e.failStart {
		return nil, fmt.Errorf("boom")
	}
	h := &fakeHandle{id: req.Task.ID}
	e.handles = append(e.handles, h)
	return h, nil
}
func (e *fakeEngine) Close() error { return nil }

type collector struct {
	mu     sync.Mutex
	events []engine.Event
}

func (c *collector) Emit(ev engine.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
}

func fixedClock() func() time.Time {
	base := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	n := 0
	return func() time.Time { n++; return base.Add(time.Duration(n) * time.Second) }
}

func TestPriorityOrderingAndConcurrencyCap(t *testing.T) {
	store := newMemStore()
	fe := &fakeEngine{}
	router := NewEngineRouter()
	router.Register(domain.SourceHTTP, fe)
	col := &collector{}
	orch, err := New(Options{Store: store, Router: router, Sink: col, MaxConcur: 2, Clock: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}

	src := domain.DownloadSource{Kind: domain.SourceHTTP, URL: "https://x.example/a.bin"}
	low, _ := orch.Submit(src, domain.DownloadPolicy{})
	low.Priority = 1
	store.Save(low)
	high, _ := orch.Submit(src, domain.DownloadPolicy{})
	high.Priority = 9
	store.Save(high)

	first, err := orch.StartNext()
	if err != nil || first == nil {
		t.Fatalf("start1: %v %v", first, err)
	}
	if first.ID != high.ID {
		t.Fatalf("prioridade maior deveria sair primeiro; obtive %+v", first)
	}
	if _, err := orch.StartNext(); err != nil {
		t.Fatal(err)
	}
	third, err := orch.StartNext() // cap=2 atingido -> nil sem erro
	if err != nil {
		t.Fatal(err)
	}
	if third != nil {
		t.Fatal("respeitar MaxConcur=2")
	}
	if len(col.events) == 0 {
		t.Error("eventos de estado deveriam ser emitidos")
	}
}

func TestUnsupportedSourceFailsWithDiagnosis(t *testing.T) {
	store := newMemStore()
	router := NewEngineRouter() // vazio
	orch, _ := New(Options{Store: store, Router: router, Clock: fixedClock()})
	tk, _ := orch.Submit(domain.DownloadSource{Kind: domain.SourceMagnet}, domain.DownloadPolicy{})
	_, err := orch.StartNext()
	if err == nil {
		t.Fatal("sem motor p/ magnet deve falhar")
	}
	got, _ := store.Get(tk.ID)
	if got.State != domain.StateFailed || got.Error == nil || got.Error.Class != domain.ErrUnsupportedSource {
		t.Fatalf("esperava failed+unsupported_source, obtive %v %+v", got.State, got.Error)
	}
	if got.Error.Action == "" {
		t.Error("falha sem ação recomendada ao utilizador")
	}
}

func TestRecoverAfterCrashMarksRunningAsRetryable(t *testing.T) {
	store := newMemStore()
	fe := &fakeEngine{}
	router := NewEngineRouter()
	router.Register(domain.SourceHTTP, fe)
	orch, _ := New(Options{Store: store, Router: router, Clock: fixedClock()})
	tk, _ := orch.Submit(domain.DownloadSource{Kind: domain.SourceHTTP, URL: "https://x/a"}, domain.DownloadPolicy{})
	if _, err := orch.StartNext(); err != nil {
		t.Fatal(err)
	}
	// simular crash: novo orquestrador sobre o mesmo store
	orch2, _ := New(Options{Store: store, Router: router, Clock: fixedClock()})
	n, err := orch2.Recover()
	if err != nil || n != 1 {
		t.Fatalf("recuperação esperava 1 tarefa, obtive %d %v", n, err)
	}
	got, _ := store.Get(tk.ID)
	if got.State != domain.StatePending {
		t.Fatalf("após crash a tarefa deve voltar à fila, estado=%s", got.State)
	}
	if got.Error == nil || !got.Error.Retryable {
		t.Error("erro de recuperação deve ser marcado retomável")
	}
}

func TestCancelIsTerminal(t *testing.T) {
	store := newMemStore()
	fe := &fakeEngine{}
	router := NewEngineRouter()
	router.Register(domain.SourceHTTP, fe)
	orch, _ := New(Options{Store: store, Router: router, Clock: fixedClock()})
	tk, _ := orch.Submit(domain.DownloadSource{Kind: domain.SourceHTTP, URL: "https://x/a"}, domain.DownloadPolicy{})
	if _, err := orch.StartNext(); err != nil {
		t.Fatal(err)
	}
	if err := orch.Cancel(tk.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := store.Get(tk.ID)
	if got.State != domain.StateCancelled {
		t.Fatalf("esperava cancelled, obtive %s", got.State)
	}
	if !fe.handles[0].closed {
		t.Error("handle não foi cancelado no motor")
	}
}
