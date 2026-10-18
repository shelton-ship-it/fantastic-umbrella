// Package storage implementa o Módulo 8 — persistência estruturada local.
//
// Decisões registadas (ADR-001, coerentes com o briefing):
//   - SQLite via modernc.org/sqlite: driver puro-Go (CGO-free), licença MIT,
//     cross-compila para Windows/Android-NIF sem toolchain C. mattn/go-sqlite3
//     foi rejeitado por exigir CGO nos alvos escolhidos.
//   - Uma única base de dados para metadados de tarefas, estado de recuperação,
//     índice local de hashes e registo de licenças verificadas. Preferências
//     simples vivem no pacote config (JSON versionado) — duas bases concorrentes
//     para os mesmos dados são proibidas pelo briefing.
//   - O storage NÃO conhece HTTP nem BitTorrent: serializa apenas domain.
//   - Nunca é guardada qualquer chave privada; da licença guarda-se apenas o
//     resultado da VERIFICAÇÃO (status + campos públicos já assinados).
package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite" // driver CGO-free (MIT)

	"streamvault/core/domain"
)

// SchemaVersion atual da base. Migrações destrutivas só com autorização;
// versão futura lida por uma app antiga é recusada com erro claro.
const SchemaVersion = 1

// Store persiste tarefas de download (implementa orchestrator.Store) e o
// estado de recuperação/integridade associado.
type Store struct {
	db *sql.DB
}

// Options de abertura.
type Options struct {
	Path        string        // ficheiro .db ("" => in-memory para testes)
	BusyTimeout time.Duration // espera por locks em vez de falhar de imediato
}

// Open abre (ou cria) a base e aplica o schema idempotentemente.
func Open(o Options) (*Store, error) {
	dsn := o.Path
	if dsn == "" {
		dsn = ":memory:"
	} else if dir := filepath.Dir(dsn); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("storage: diretório da base: %w", err)
		}
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	busy := o.BusyTimeout / time.Millisecond
	if busy <= 0 {
		busy = 5000
	}
	// WAL: leituras não bloqueiam escrita; busy_timeout evita SQLITE_BUSY
	// espúrio quando UI e worker partilham a base.
	dsn += sep + "_pragma=journal_mode(WAL)&_pragma=busy_timeout(" + fmt.Sprintf("%d", int64(busy)) + ")"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("storage: abrir: %w", err)
	}
	// Single-writer design: pool de 1 conexão evita deadlocks de upgrade de lock.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("storage: ping: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// migrate aplica o schema corrente e recusa versões futuras.
func (s *Store) migrate() error {
	// bootstrap: a tabela meta pode ainda não existir em base nova —
	// criar antes de ler a versão (ler sem tabela seria erro espúrio).
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS meta (
		key   TEXT PRIMARY KEY,
		value INTEGER NOT NULL
	)`); err != nil {
		return fmt.Errorf("storage: bootstrap meta: %w", err)
	}
	var cur int64
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key='schema_version'`).Scan(&cur)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("storage: ler versão: %w", err)
	}
	if cur > SchemaVersion {
		return fmt.Errorf("storage: base com schema %d é mais recente que esta aplicação (%d); atualize a aplicação em vez de migrar às cegas", cur, SchemaVersion)
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS meta (
			key   TEXT PRIMARY KEY,
			value INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS tasks (
			id           TEXT PRIMARY KEY,
			state        INTEGER NOT NULL,
			priority     INTEGER NOT NULL DEFAULT 0,
			kind         TEXT NOT NULL,
			info_hash    TEXT NOT NULL DEFAULT '',
			display_name TEXT NOT NULL DEFAULT '',
			bytes_done   INTEGER NOT NULL DEFAULT 0,
			bytes_total  INTEGER NOT NULL DEFAULT -1,
			version      INTEGER NOT NULL DEFAULT 1,
			created_ms   INTEGER NOT NULL,
			updated_ms   INTEGER NOT NULL,
			blob         BLOB NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_tasks_state_prio ON tasks(state, priority DESC, created_ms ASC)`,
		`CREATE TABLE IF NOT EXISTS resume_state (
			task_id      TEXT PRIMARY KEY REFERENCES tasks(id) ON DELETE CASCADE,
			engine       TEXT NOT NULL,            -- 'http' | 'bittorrent'
			temp_path    TEXT NOT NULL DEFAULT '', -- ficheiro temporário em disco
			offsets_json TEXT NOT NULL DEFAULT '{}', -- intervalos concluídos p/ retoma
			remote_etag  TEXT NOT NULL DEFAULT '',
			remote_size  INTEGER NOT NULL DEFAULT -1,
			remote_mtime TEXT NOT NULL DEFAULT '',
			updated_ms   INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS hash_index (
			sha256_hex  TEXT PRIMARY KEY,        -- hash do CONTEÚDO integral (duplicados exatos)
			path        TEXT NOT NULL,           -- caminho absoluto local validado
			size_bytes  INTEGER NOT NULL,
			mtime_ms    INTEGER NOT NULL,
			verified_ms INTEGER NOT NULL,
			source_task TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_hash_path ON hash_index(path)`,
		`CREATE TABLE IF NOT EXISTS license_records (
			license_id        TEXT PRIMARY KEY,
			product_id        TEXT NOT NULL,
			edition           TEXT NOT NULL,
			key_id            TEXT NOT NULL,
			status            INTEGER NOT NULL, -- status de verificação (license.Status)
			entitlements_json TEXT NOT NULL DEFAULT '{}',
			validated_ms      INTEGER NOT NULL,
			expires_ms        INTEGER NOT NULL DEFAULT 0, -- 0 = permanente
			blob              BLOB NOT NULL               -- documento público assinado (sem segredos)
		)`,
		`INSERT OR IGNORE INTO meta(key,value) VALUES('schema_version',1)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("storage: migration: %w", err)
		}
	}
	if cur < SchemaVersion {
		if _, err := s.db.Exec(`UPDATE meta SET value=? WHERE key='schema_version'`, SchemaVersion); err != nil {
			return fmt.Errorf("storage: gravar versão: %w", err)
		}
	}
	return nil
}

// ---------- Tarefas (contrato orchestrator.Store) ----------

// Save insere ou atualiza com optimistic concurrency: se a linha existir com
// version superior à esperada, a gravação é recusada (perda silenciosa é
// proibida pelo briefing — melhor erro do que sobrescrever progresso).
func (s *Store) Save(t *domain.DownloadTask) error {
	blob, err := domain.MarshalTask(t)
	if err != nil {
		return err
	}
	// Insert-if-absent primeiro: elimina a race update-vs-insert e mantém o
	// contrato "nunca esmagar estado alheio" (INSERT simples, não REPLACE).
	_, insErr := s.db.Exec(`INSERT INTO tasks(id,state,priority,kind,info_hash,display_name,
			bytes_done,bytes_total,version,created_ms,updated_ms,blob)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		t.ID, int(t.State), t.Priority, string(t.Source.Kind), t.Source.InfoHash,
		t.Source.DisplayName, t.Progress.BytesDone, t.Progress.BytesTotal,
		1, t.CreatedAt.UnixMilli(), t.UpdatedAt.UnixMilli(), blob)
	if insErr == nil {
		t.Version = 1 // linha criada; cópia em memória espelha o disco
		return nil
	}
	if !strings.Contains(insErr.Error(), "UNIQUE") {
		return fmt.Errorf("storage: save(insert): %w", insErr)
	}
	// Já existia → update com optimistic concurrency sobre a version atual.
	res, err := s.db.Exec(`UPDATE tasks SET state=?,priority=?,kind=?,info_hash=?,display_name=?,
			bytes_done=?,bytes_total=?,version=?,updated_ms=?,blob=?
		WHERE id=? AND version=?`,
		int(t.State), t.Priority, string(t.Source.Kind), t.Source.InfoHash,
		t.Source.DisplayName, t.Progress.BytesDone, t.Progress.BytesTotal,
		t.Version+1, t.UpdatedAt.UnixMilli(), blob, t.ID, t.Version)
	if err != nil {
		return fmt.Errorf("storage: save(update): %w", err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		t.Version++
		return nil
	}
	return fmt.Errorf("storage: conflito de versão na tarefa %s (estado mudou em paralelo; recarregue)", t.ID)
}

// Get carrega uma tarefa por ID.
func (s *Store) Get(id string) (*domain.DownloadTask, error) {
	var blob []byte
	var version int64
	err := s.db.QueryRow(`SELECT blob, version FROM tasks WHERE id=?`, id).Scan(&blob, &version)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("storage: tarefa %s não existe", id)
	}
	if err != nil {
		return nil, fmt.Errorf("storage: get: %w", err)
	}
	t, err := domain.UnmarshalTask(blob)
	if err != nil {
		return nil, err
	}
	t.Version = version
	return t, nil
}

// List devolve todas as tarefas ordenadas por criação (estável p/ fila).
func (s *Store) List() ([]*domain.DownloadTask, error) {
	rows, err := s.db.Query(`SELECT blob, version FROM tasks ORDER BY created_ms ASC`)
	if err != nil {
		return nil, fmt.Errorf("storage: list: %w", err)
	}
	defer rows.Close()
	var out []*domain.DownloadTask
	for rows.Next() {
		var blob []byte
		var version int64
		if err := rows.Scan(&blob, &version); err != nil {
			return nil, err
		}
		t, err := domain.UnmarshalTask(blob)
		if err != nil {
			// Metadados corrompidos: reportar, nunca ignorar calado.
			return nil, fmt.Errorf("storage: task corrompida: %w", err)
		}
		t.Version = version
		out = append(out, t)
	}
	return out, rows.Err()
}

// Delete remove a tarefa e o seu estado de recuperação.
func (s *Store) Delete(id string) error {
	if _, err := s.db.Exec(`DELETE FROM resume_state WHERE task_id=?`, id); err != nil {
		return fmt.Errorf("storage: delete resume: %w", err)
	}
	res, err := s.db.Exec(`DELETE FROM tasks WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("storage: delete: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("storage: tarefa %s não existe para apagar", id)
	}
	return nil
}

// ---------- Estado de recuperação (Módulo 7 ↔ Módulo 8) ----------

// ResumeState descreve o necessário para retomar após fecho/crash.
// Distingue claramente o que é LOCAL (offsets/temp_path) do que é REMOTO
// (etag/size/mtime) — comparar os dois permite dizer se o recurso remoto
// mudou (falha remota) ou se os dados locais estão corrompidos.
type ResumeState struct {
	TaskID      string
	Engine      string
	TempPath    string
	Offsets     map[string]int64 // segmento -> bytes escritos (ex.: "0-1048575")
	RemoteETag  string
	RemoteSize  int64
	RemoteMTime string
	UpdatedAt   time.Time
}

func (s *Store) SaveResume(rs ResumeState) error {
	off, err := marshalOrderedInt64(rs.Offsets)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO resume_state(task_id,engine,temp_path,offsets_json,
			remote_etag,remote_size,remote_mtime,updated_ms)
		VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(task_id) DO UPDATE SET engine=excluded.engine, temp_path=excluded.temp_path,
			offsets_json=excluded.offsets_json, remote_etag=excluded.remote_etag,
			remote_size=excluded.remote_size, remote_mtime=excluded.remote_mtime,
			updated_ms=excluded.updated_ms`,
		rs.TaskID, rs.Engine, rs.TempPath, off, rs.RemoteETag,
		rs.RemoteSize, rs.RemoteMTime, rs.UpdatedAt.UnixMilli())
	if err != nil {
		return fmt.Errorf("storage: save resume: %w", err)
	}
	return nil
}

// LoadResume devolve nil,nil quando não existe estado de retoma — o chamador
// deve comunicar a limitação ("retoma não disponível"), não assumir sucesso.
func (s *Store) LoadResume(taskID string) (*ResumeState, error) {
	var rs ResumeState
	var off string
	var ms int64
	err := s.db.QueryRow(`SELECT engine,temp_path,offsets_json,remote_etag,remote_size,remote_mtime,updated_ms
		FROM resume_state WHERE task_id=?`, taskID).
		Scan(&rs.Engine, &rs.TempPath, &off, &rs.RemoteETag, &rs.RemoteSize, &rs.RemoteMTime, &ms)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("storage: load resume: %w", err)
	}
	rs.TaskID = taskID
	rs.UpdatedAt = time.UnixMilli(ms).UTC()
	rs.Offsets, err = unmarshalOffsets(off)
	if err != nil {
		return nil, err
	}
	return &rs, nil
}

// ---------- Índice local de hashes (Módulo 9: duplicados exatos) ----------

type HashEntry struct {
	SHA256Hex  string
	Path       string
	SizeBytes  int64
	ModTime    time.Time
	VerifiedAt time.Time
	SourceTask string
}

func (s *Store) UpsertHash(e HashEntry) error {
	h := strings.ToLower(e.SHA256Hex)
	if len(h) != 64 || !isLowerHex(h) {
		return fmt.Errorf("storage: hash inválido (esperado sha256 hex de 64 chars)")
	}
	_, err := s.db.Exec(`INSERT INTO hash_index(sha256_hex,path,size_bytes,mtime_ms,verified_ms,source_task)
		VALUES(?,?,?,?,?,?)
		ON CONFLICT(sha256_hex) DO UPDATE SET path=excluded.path, size_bytes=excluded.size_bytes,
			mtime_ms=excluded.mtime_ms, verified_ms=excluded.verified_ms, source_task=excluded.source_task`,
		h, e.Path, e.SizeBytes, e.ModTime.UnixMilli(),
		e.VerifiedAt.UnixMilli(), e.SourceTask)
	if err != nil {
		return fmt.Errorf("storage: upsert hash: %w", err)
	}
	return nil
}

// FindByHash lista caminhos com conteúdo EXATAMENTE igual (hash integral —
// nome igual não prova duplicado, por isso a API expõe apenas hash).
func (s *Store) FindByHash(sha256hex string) ([]HashEntry, error) {
	rows, err := s.db.Query(`SELECT sha256_hex,path,size_bytes,mtime_ms,verified_ms,source_task
		FROM hash_index WHERE sha256_hex=?`, strings.ToLower(sha256hex))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HashEntry
	for rows.Next() {
		var e HashEntry
		var mt, vm int64
		if err := rows.Scan(&e.SHA256Hex, &e.Path, &e.SizeBytes, &mt, &vm, &e.SourceTask); err != nil {
			return nil, err
		}
		e.ModTime = time.UnixMilli(mt).UTC()
		e.VerifiedAt = time.UnixMilli(vm).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------- Registo de licenças verificadas (apenas dados PÚBLICOS) ----------

type LicenseRecord struct {
	LicenseID    string
	ProductID    string
	Edition      string
	KeyID        string
	Status       int // status de verificação (license.Status)
	Entitlements map[string]bool
	ValidatedAt  time.Time
	ExpiresAtMS  int64 // 0 = permanente
	DocumentBlob []byte
}

func (s *Store) SaveLicense(r LicenseRecord) error {
	ent, err := marshalBoolMap(r.Entitlements)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO license_records(license_id,product_id,edition,key_id,status,
			entitlements_json,validated_ms,expires_ms,blob)
		VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(license_id) DO UPDATE SET status=excluded.status, entitlements_json=excluded.entitlements_json,
			validated_ms=excluded.validated_ms, expires_ms=excluded.expires_ms, blob=excluded.blob`,
		r.LicenseID, r.ProductID, r.Edition, r.KeyID, r.Status, ent,
		r.ValidatedAt.UnixMilli(), r.ExpiresAtMS, r.DocumentBlob)
	if err != nil {
		return fmt.Errorf("storage: save license: %w", err)
	}
	return nil
}

func (s *Store) LatestLicense() (*LicenseRecord, error) {
	var r LicenseRecord
	var ent string
	var vm, ex int64
	err := s.db.QueryRow(`SELECT license_id,product_id,edition,key_id,status,entitlements_json,
		validated_ms,expires_ms,blob FROM license_records ORDER BY validated_ms DESC LIMIT 1`).
		Scan(&r.LicenseID, &r.ProductID, &r.Edition, &r.KeyID, &r.Status, &ent, &vm, &ex, &r.DocumentBlob)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.ValidatedAt = time.UnixMilli(vm).UTC()
	r.ExpiresAtMS = ex
	r.Entitlements, err = unmarshalBoolMap(ent)
	return &r, err
}

// ---------- helpers ----------

func isLowerHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func marshalOrderedInt64(m map[string]int64) (string, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%q:%d", k, m[k])
	}
	b.WriteByte('}')
	return b.String(), nil
}

func unmarshalOffsets(s string) (map[string]int64, error) {
	if s == "" || s == "{}" {
		return map[string]int64{}, nil
	}
	m := map[string]int64{}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, fmt.Errorf("storage: offsets corrompidos: %w", err)
	}
	return m, nil
}

func marshalBoolMap(m map[string]bool) (string, error) {
	if m == nil {
		m = map[string]bool{}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%q:%t", k, m[k])
	}
	b.WriteByte('}')
	return b.String(), nil
}

func unmarshalBoolMap(s string) (map[string]bool, error) {
	m := map[string]bool{}
	if s == "" || s == "{}" {
		return m, nil
	}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, fmt.Errorf("storage: entitlements corrompidos: %w", err)
	}
	return m, nil
}
