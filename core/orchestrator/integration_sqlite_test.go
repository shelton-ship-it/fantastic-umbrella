package orchestrator

import (
	"context"
	"testing"
	"time"

	"streamvault/core/domain"
	"streamvault/core/engine"
	"streamvault/core/storage"
)

// integração real: Orchestrator + storage.SQLite (ficheiro temporário).
// Prova do critério de conclusão da Fase 4: HTTP e BitTorrent (via fake com
// as mesmas capacidades declaradas) partilham a MESMA fila persistente, sem
// qualquer acoplamento entre orquestrador e motores concretos.

func newSQLiteOrch(t *testing.T, maxConc int) (*Orchestrator, *storage.Store, *collector) {
	t.Helper()
	st, err := storage.Open(storage.Options{Path: t.TempDir() + "/q.db"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	router := NewEngineRouter()
	router.Register(domain.SourceHTTP, &fakeEngine{caps: engine.Capabilities{SupportsPause: true, SupportsResume: true}})
	router.Register(domain.SourceMagnet, &fakeEngine{caps: engine.Capabilities{SupportsVerify: true}})
	col := &collector{}
	fan := NewFanout(64)
	fan.Subscribe(col.Emit)
	fan.Subscribe(orchObserveHolder{}) // placeholder substituído abaixo
	orch, err := New(Options{Store: st, Router: router, Sink: fan, MaxConcur: maxConc, Clock: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	// desliga placeholder; liga observador real do orquestrador
	fan2 := fan // mesma instância; re-subscribe limpo não é necessário porque
	// orchObserveHolder é no-op — o teste chama ObserveEngine diretamente.
	_ = fan2
	return orch, st, col
}

type orchObserveHolder struct{}

func (orchObserveHolder) Emit(engine.Event) {}

func httpSrc(url string) domain.DownloadSource {
	return domain.DownloadSource{Kind: domain.SourceHTTP, URL: url, DisplayName: "f.bin"}
}

func magnetSrc(h string) domain.DownloadSource {
	return domain.DownloadSource{Kind: domain.SourceMagnet, InfoHash: h, DisplayName: "movie.mkv"}
}

// Fila mista HTTP+magnet persiste e recupera através de SQLite real.
func TestQueueSurvivesRestartWithSQLite(t *testing.T) {
	dir := t.TempDir()
	st, err := storage.Open(storage.Options{Path: dir + "/q.db"})
	if err != nil {
		t.Fatal(err)
	}
	router := NewEngineRouter()
	router.Register(domain.SourceHTTP, &fakeEngine{caps: engine.Capabilities{SupportsPause: true}})
	router.Register(domain.SourceMagnet, &fakeEngine{caps: engine.Capabilities{SupportsVerify: true}})
	orch, err := New(Options{Store: st, Router: router, MaxConcur: 1, Clock: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	h, _ := orch.Submit(httpSrc("https://e.com/a.zip?tok=x"), domain.DownloadPolicy{})
	m, _ := orch.Submit(magnetSrc("0123456789abcdef0123456789abcdef01234567"), domain.DownloadPolicy{})

	// inicia uma (capacidade 1) — fica running em memória E no disco
	if _, err := orch.StartNext(); err != nil {
		t.Fatal(err)
	}
	st.Close() // simula fecho/crash da aplicação

	// "reinício": nova Store sobre o mesmo ficheiro, novo orquestrador
	st2, err := storage.Open(storage.Options{Path: dir + "/q.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	orch2, err := New(Options{Store: st2, Router: router, MaxConcur: 2, Clock: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	n, err := orch2.Recover()
	if err != nil || n != 1 {
		t.Fatalf("recuperação esperava 1 tarefa running fantasma, obtido %d (%v)", n, err)
	}
	gotH, err := st2.Get(h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotH.State != domain.StatePending {
		t.Errorf("após recover, tarefa running deveria voltar a pending; está %s", gotH.State)
	}
	gotM, _ := st2.Get(m.ID)
	if gotM.State != domain.StatePending {
		t.Errorf("magnet pendente perdido: %s", gotM.State)
	}
	// prioridade sobreviveu ao reinício
	gotM.Priority = 5
	gotM.UpdatedAt = time.Now().UTC()
	if err := st2.Save(gotM); err != nil {
		t.Fatal(err)
	}
	st2.Close()
	st3, _ := storage.Open(storage.Options{Path: dir + "/q.db"})
	defer st3.Close()
	gm, _ := st3.Get(m.ID)
	if gm.Priority != 5 {
		t.Error("reordenação não persistiu")
	}
}

// Motor conclui → evento tratado por ObserveEngine respeita a política:
// com RequireIntegrity, um EventCompleted sem Verifying NÃO marca completed.
func TestTerminalEventRespectsIntegrityPolicy(t *testing.T) {
	orch, st, _ := newSQLiteOrch(t, 2)
	task, _ := orch.Submit(httpSrc("https://e.com/v.mp4"), domain.DownloadPolicy{RequireIntegrity: domain.IntegritySHA256})
	if _, err := orch.StartNext(); err != nil {
		t.Fatal(err)
	}
	// motor afirma conclusão direta (atalho indevido)
	changed := orch.ObserveEngine(engine.Event{Kind: engine.EventCompleted, TaskID: task.ID, State: domain.StateCompleted})
	if !changed {
		t.Fatal("evento terminal deveria libertar capacidade")
	}
	got, _ := st.Get(task.ID)
	if got.State == domain.StateCompleted {
		t.Error("política de integridade foi contornada pelo evento do motor")
	}
}

// Erro reportado pelo motor é persistido como falha terminal com diagnóstico.
func TestEngineErrorPersistedAsFailure(t *testing.T) {
	orch, st, _ := newSQLiteOrch(t, 2)
	task, _ := orch.Submit(magnetSrc("0123456789abcdef0123456789abcdef01234567"), domain.DownloadPolicy{})
	if _, err := orch.StartNext(); err != nil {
		t.Fatal(err)
	}
	e := domain.NewError(domain.ErrConnectionLost, nil, "perda de peers", "Aguardar mais peers.", domain.CertaintyHeuristic, true)
	orch.ObserveEngine(engine.Event{Kind: engine.EventError, TaskID: task.ID, Error: e})
	got, err := st.Get(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != domain.StateFailed || got.Error == nil || got.Error.Class != domain.ErrConnectionLost {
		t.Errorf("falha do motor não persistida corretamente: %s %+v", got.State, got.Error)
	}
}

// Reordenação via SetPriority altera a ordem efetiva de StartNext na base real.
func TestReorderChangesExecutionOrder(t *testing.T) {
	orch, st, _ := newSQLiteOrch(t, 1)
	a, _ := orch.Submit(httpSrc("https://e.com/a"), domain.DownloadPolicy{})
	b, _ := orch.Submit(httpSrc("https://e.com/b"), domain.DownloadPolicy{})
	if err := orch.SetPriority(b.ID, 10); err != nil {
		t.Fatal(err)
	}
	first, err := orch.StartNext()
	if err != nil || first == nil || first.ID != b.ID {
		t.Fatalf("prioridade ignorada: primeira=%v err=%v", first, err)
	}
	// tentativa de reordenar ativa deve ser recusada com erro claro
	if err := orch.SetPriority(a.ID, 99); err == nil {
		// a ainda está pending (capacidade 1 ocupada por b) — isso É permitido
		_ = err
	}
	// mas b está running: deve recusar
	if err := orch.SetPriority(b.ID, 1); err == nil {
		t.Error("reordenar tarefa ativa deveria ser recusado honestamente")
	}
	all, _ := st.List()
	if len(all) != 2 {
		t.Errorf("fila corrompida após reorder: %d tarefas", len(all))
	}
}

// Shutdown ordenado liberta handles (contexto cancelado chega aos motores).
func TestShutdownCancelsContext(t *testing.T) {
	orch, _, _ := newSQLiteOrch(t, 2)
	eng := &fakeEngine{caps: engine.Capabilities{}}
	orch.router.Register(domain.SourceHTTP, eng)
	orch.Submit(httpSrc("https://e.com/x"), domain.DownloadPolicy{})
	orch.StartNext()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := orch.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-eng.lastCtx.Done():
	default:
		t.Error("shutdown não propagou cancelamento ao motor")
	}
}
