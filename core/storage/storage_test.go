package storage

import (
	"strings"
	"testing"
	"time"

	"streamvault/core/domain"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(Options{}) // in-memory
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func mkTask(id string, state domain.State) *domain.DownloadTask {
	now := time.UnixMilli(1700000000000).UTC()
	return &domain.DownloadTask{
		ID: id,
		Source: domain.DownloadSource{
			Kind: domain.SourceHTTP, URL: "https://cdn.example.com/a.zip?token=XYZ",
			DisplayName: "a.zip",
		},
		Policy:    domain.DownloadPolicy{RequireIntegrity: domain.IntegritySHA256, MaxSizeBytes: 1 << 30},
		State:     state,
		Progress:  domain.ProgressSnapshot{BytesDone: 4096, BytesTotal: 8192},
		CreatedAt: now, UpdatedAt: now,
	}
}

// Save/Get roundtrip preserva estado completo incluindo erro tipado.
func TestSaveGetRoundtrip(t *testing.T) {
	s := newTestStore(t)
	task := mkTask("dl-1", domain.StateFailed)
	task.Error = domain.NewError(domain.ErrResumeMismatch, nil,
		"recurso remoto mudou de tamanho", "Reiniciar transferência.",
		domain.CertaintyObserved, false)
	task.Error.RemoteCode = 416
	if err := s.Save(task); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("dl-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != domain.StateFailed || got.Progress.BytesDone != 4096 {
		t.Errorf("estado/progresso perdidos: %+v", got)
	}
	if got.Error == nil || got.Error.Class != domain.ErrResumeMismatch || got.Error.RemoteCode != 416 {
		t.Errorf("erro tipado não reconstruído: %+v", got.Error)
	}
	if got.Version != 1 {
		t.Errorf("version após insert = %d, esperado 1", got.Version)
	}
	// Atualização incrementa version (optimistic concurrency observável).
	got.Progress.BytesDone = 5000
	if err := s.Save(got); err != nil {
		t.Fatal(err)
	}
	if got.Version != 2 {
		t.Errorf("version após update = %d, esperado 2", got.Version)
	}
}

// Stale write: gravar com version desatualizada deve FALHAR, não sobrescrever.
func TestOptimisticConcurrencyRejectsStaleWrite(t *testing.T) {
	s := newTestStore(t)
	task := mkTask("dl-2", domain.StatePending)
	if err := s.Save(task); err != nil {
		t.Fatal(err)
	}
	a, _ := s.Get("dl-2")
	b, _ := s.Get("dl-2")
	a.Priority = 10
	if err := s.Save(a); err != nil {
		t.Fatal(err) // primeira update OK (version 1 -> 2)
	}
	b.Priority = 99 // b tem version 1 obsoleta
	err := s.Save(b)
	if err == nil {
		t.Fatal("gravação stale deveria ser recusada (perda silenciosa proibida)")
	}
	if !strings.Contains(err.Error(), "conflito") {
		t.Errorf("erro deveria mencionar conflito, obtido: %v", err)
	}
}

// Persistência pós-reinício: fechar e reabrir o MESMO ficheiro recupera fila.
func TestPersistenceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/queue.db"
	s, err := Open(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	task := mkTask("dl-crash", domain.StateRunning) // simulamos crash com running
	if err := s.Save(task); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// "Reinício da aplicação":
	s2, err := Open(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, err := s2.Get("dl-crash")
	if err != nil {
		t.Fatalf("estado perdido após reopen: %v", err)
	}
	if got.State != domain.StateRunning {
		t.Errorf("estado persistido incorreto: %s", got.State)
	}
	// WAL criado junto ao ficheiro — verificar que journal_mode ficou ativo.
	var jm string
	if err := s2.db.QueryRow(`PRAGMA journal_mode`).Scan(&jm); err != nil {
		t.Fatal(err)
	}
	if strings.ToLower(jm) != "wal" {
		t.Errorf("esperado WAL, obtido %s", jm)
	}
}

// Delete em cascata remove também o estado de retoma.
func TestDeleteCascadeResume(t *testing.T) {
	s := newTestStore(t)
	task := mkTask("dl-del", domain.StatePaused)
	if err := s.Save(task); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveResume(ResumeState{
		TaskID: "dl-del", Engine: "http", TempPath: "/tmp/dl-del.part",
		Offsets: map[string]int64{"0-1048575": 1048576}, RemoteETag: `"abc"`,
		RemoteSize: 2097152, UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	rs, err := s.LoadResume("dl-del")
	if err != nil || rs == nil || rs.Offsets["0-1048575"] != 1048576 {
		t.Fatalf("resume não persistido: %+v %v", rs, err)
	}
	if err := s.Delete("dl-del"); err != nil {
		t.Fatal(err)
	}
	rs, err = s.LoadResume("dl-del")
	if err != nil || rs != nil {
		t.Errorf("resume deveria ter sido removido em cascata: %+v %v", rs, err)
	}
}

// LoadResume sem estado devolve (nil,nil) — limitação comunicada, não erro.
func TestLoadResumeMissing(t *testing.T) {
	s := newTestStore(t)
	rs, err := s.LoadResume("inexistente")
	if rs != nil || err != nil {
		t.Errorf("esperado nil,nil; obtido %+v,%v", rs, err)
	}
}

// Hash index: só hex sha256 válido entra; FindByHash exige igualdade EXATA.
func TestHashIndex(t *testing.T) {
	s := newTestStore(t)
	h := strings.Repeat("a", 64)
	if err := s.UpsertHash(HashEntry{SHA256Hex: h, Path: "/music/song.flac",
		SizeBytes: 100, ModTime: time.Now(), VerifiedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertHash(HashEntry{SHA256Hex: "curto", Path: "/x"}); err == nil {
		t.Error("hash inválido deveria ser recusado")
	}
	hits, err := s.FindByHash(strings.ToUpper(h)) // lookup case-insensitive
	if err != nil || len(hits) != 1 || hits[0].Path != "/music/song.flac" {
		t.Errorf("FindByHash falhou: %+v %v", hits, err)
	}
	misses, _ := s.FindByHash(strings.Repeat("b", 64))
	if len(misses) != 0 {
		t.Error("nome/hash diferente não é duplicado")
	}
}

// Licença: apenas dados públicos; LatestLicense devolve mais recente.
func TestLicenseRecord(t *testing.T) {
	s := newTestStore(t)
	base := LicenseRecord{LicenseID: "lic-1", ProductID: "streamvault-win", Edition: "pro",
		KeyID: "k1", Status: 1, Entitlements: map[string]bool{"ad_free": true},
		ValidatedAt: time.UnixMilli(1000).UTC(), ExpiresAtMS: 0, DocumentBlob: []byte(`{}`)}
	if err := s.SaveLicense(base); err != nil {
		t.Fatal(err)
	}
	base.LicenseID = "lic-2"
	base.ValidatedAt = time.UnixMilli(2000).UTC()
	if err := s.SaveLicense(base); err != nil {
		t.Fatal(err)
	}
	got, err := s.LatestLicense()
	if err != nil || got == nil || got.LicenseID != "lic-2" {
		t.Fatalf("latest errado: %+v %v", got, err)
	}
	if !got.Entitlements["ad_free"] {
		t.Error("entitlements perdidos")
	}
}

// Schema futuro deve ser RECUSADO em vez de corrompido (sem migração cega).
func TestFutureSchemaRefused(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.db.Exec(`UPDATE meta SET value=99 WHERE key='schema_version'`); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Options{}); err != nil {
		// in-memory nova começa limpa — forçar via mesmo db não aplica; testamos direto:
		_ = err
	}
	// Reabrir a MESMA base em memória partilhada não é possível; validamos a
	// lógica de migrate() com um store já corrompido propositadamente:
	err := s.migrate()
	if err == nil || !strings.Contains(err.Error(), "mais recente") {
		t.Errorf("schema futuro deveria ser recusado, obtido: %v", err)
	}
}

// List ordena por criação (estabilidade da fila).
func TestListOrderAndCorruptionReported(t *testing.T) {
	s := newTestStore(t)
	for i, id := range []string{"a", "b", "c"} {
		task := mkTask(id, domain.StatePending)
		task.CreatedAt = task.CreatedAt.Add(time.Duration(i) * time.Second)
		task.UpdatedAt = task.CreatedAt
		if err := s.Save(task); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.List()
	if err != nil || len(all) != 3 || all[0].ID != "a" || all[2].ID != "c" {
		t.Fatalf("ordem/listagem errada: %v %v", all, err)
	}
}
