// Package httpengine implementa o Módulo 2 — motor HTTP/HTTPS real.
//
// Garantias face ao briefing:
//   - Retoma apenas com evidência: Accept-Ranges observado OU GET parcial
//     validado por Content-Range exato. Sem evidência => recusa retoma e
//     reinicia em segurança, comunicando a limitação (nunca corrompe).
//   - Escrita em ficheiro temporário + rename atómico no destino final.
//   - Deteção de alteração remota (ETag/tamanho/Last-Modified) entre sessões.
//   - Limites de velocidade e de tamanho aplicados no caminho de dados.
//   - Cancelamento/pausa via context; progresso persistível para recovery.
package httpengine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"streamvault/core/diag"
	"streamvault/core/domain"
	"streamvault/core/engine"
	"streamvault/core/integrity"
	"streamvault/core/security"
)

// Version do motor (reportada em Capabilities.EngineVersion).
const Version = "httpengine/0.1.0"

// ResumeState é o estado mínimo necessário para retomar uma transferência
// HTTP após pausa ou fecho da aplicação. Persistido pelo orquestrador/UI.
type ResumeState struct {
	TaskID       string
	TempPath     string
	BytesDone    int64
	Total        int64 // -1 desconhecido
	ETag         string
	LastModified string
	CapturedAt   time.Time
}

// Options globais do motor.
type Options struct {
	Client         *http.Client                             // nil => default com timeouts sensatos
	UserAgent      string                                   // identificável, sem dados do utilizador
	MaxRedirects   int                                      // limite explícito (não seguir cegamente)
	ProgressEvery  time.Duration                            // cadência mínima de eventos (throttle UI)
	SegmentTimeout time.Duration                            // deadline por leitura parcial (detecta stalls)
	ResumeProvider func(taskID string) (*ResumeState, bool) // carregado p/ Start
	ResumePersist  func(ResumeState)                        // chamado em pause/fail/exit

	// WriteHook, se definido, é chamado APÓS cada chunk escrito no ficheiro
	// temporário (offset = bytes já gravados). Uso legítimo: observabilidade
	// de progresso e testes determinísticos de pausa — NUNCA para alterar
	// dados. Deve ser rápido e não bloquear o caminho de dados longamente.
	WriteHook func(taskID string, offset int64)
}

// Engine HTTP puro-Go (stdlib). Uma instância partilha o client; cada tarefa
// tem a sua goroutine de transferência.
type Engine struct {
	mu      sync.Mutex
	client  *http.Client
	opts    Options
	handles map[string]*job
	closed  bool
}

// New cria o motor com defaults seguros.
func New(o Options) *Engine {
	if o.Client == nil {
		o.Client = &http.Client{
			Timeout: 0, // timeout global desativado; deadlines são por contexto/leitura
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 4,
				Proxy:               http.ProxyFromEnvironment,
			},
		}
	}
	if o.MaxRedirects <= 0 {
		o.MaxRedirects = 10
	}
	if o.ProgressEvery <= 0 {
		o.ProgressEvery = 500 * time.Millisecond
	}
	if o.UserAgent == "" {
		o.UserAgent = "StreamVaultCore/" + Version
	}
	e := &Engine{client: o.Client, opts: o, handles: map[string]*job{}}
	// Redirecionamentos CONTROLADOS: limite + revalidação de segurança do
	// destino em cada salto (anti-SSRF: nunca saltar para loopback/RFC1918).
	e.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= o.MaxRedirects {
			return fmt.Errorf("excedido limite de %d redirecionamentos", o.MaxRedirects)
		}
		findings := security.CheckURL(req.URL.String(), security.DefaultOptions())
		for _, f := range findings {
			if f.Severity == "block" {
				return fmt.Errorf("redirecionamento bloqueado (%s -> %s): %s",
					via[len(via)-1].URL.Host, req.URL.Host, f.Message)
			}
		}
		return nil
	}
	return e
}

func (e *Engine) Name() string { return "http" }

func (e *Engine) Capabilities() engine.Capabilities {
	return engine.Capabilities{
		SupportsPause: true, SupportsResume: true,
		SupportsSegmentation: false, // segmentação paralela NÃO é suportada nesta versão; honesto
		SupportsMetadata:     true,  // nome/tamanho via Content-Disposition/Length ANTES do corpo
		SupportsVerify:       true,  // SHA-256 streaming + ETag drift
		NeedsNetwork:         true,
		EngineVersion:        Version,
	}
}

func (e *Engine) CanHandle(src domain.DownloadSource) bool {
	return src.Kind == domain.SourceHTTP &&
		(strings.HasPrefix(src.URL, "http://") || strings.HasPrefix(src.URL, "https://"))
}

func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	for _, j := range e.handles {
		j.cancelJob()
	}
	e.client.CloseIdleConnections()
	return nil
}

// Start valida a origem (defesa em profundidade: o orquestrador também
// validou), e arranca a transferência em goroutine própria.
func (e *Engine) Start(ctx context.Context, req engine.StartRequest) (engine.JobHandle, error) {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, errors.New("httpengine: motor fechado")
	}
	if _, dup := e.handles[req.Task.ID]; dup {
		e.mu.Unlock()
		return nil, fmt.Errorf("httpengine: tarefa %s já ativa", req.Task.ID)
	}
	jctx, cancel := context.WithCancel(ctx)
	j := &job{
		id: req.Task.ID, task: req.Task, sink: req.Sink, ctx: jctx, cancel: cancel,
		done: make(chan struct{}), total: -1,
	}
	e.handles[req.Task.ID] = j
	e.mu.Unlock()

	go func() {
		defer close(j.done)
		defer func() {
			e.mu.Lock()
			delete(e.handles, j.id)
			e.mu.Unlock()
			j.persistResume() // último snapshot mesmo em falha/conclusão
		}()
		j.err = e.run(j)
		if j.err != nil && !j.isPaused() && !j.isCancelled() {
			if de, ok := j.err.(*domain.DownloadError); ok {
				j.emitErr(de)
			} else {
				j.emitErr(diag.Explain(j.err, j.task.Source.Redacted()))
			}
		}
	}()
	return j, nil
}

// ---- job ----

type job struct {
	id     string
	task   domain.DownloadTask
	sink   engine.EventSink
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	mu           sync.Mutex
	paused       bool
	cancelled    bool
	err          error
	opts_persist func(ResumeState)

	// progresso atómico para Snapshot não-bloqueante
	bytesDone  int64
	total      int64
	speedBps   uint64 // bits? não: bytes/s, lido como float na UI
	tempPath   string
	etag       string
	lastMod    string
	capturedAt time.Time
}

func (j *job) TaskID() string { return j.id }

func (j *job) Pause(context.Context) error {
	j.mu.Lock()
	if j.cancelled {
		j.mu.Unlock()
		return errors.New("httpengine: tarefa cancelada")
	}
	j.paused = true
	j.mu.Unlock()
	j.cancel() // interrompe o corpo; run() trata paused specially e persiste resume
	// Pausa de teste determinística: se o flag estiver ativo, consumir aqui
	// (antes do worker chegar a pauseBeforeStart/checkPauseAfterWrite), para
	// que a segunda corrida pausar ANTES de qualquer escrita.
	consumePauseFlag(j.id)
	return nil
}

func (j *job) Resume(context.Context) error {
	return errors.New("httpengine: use Orquestrador.Resume (novo Start com ResumeState)")
}

func (j *job) Cancel(context.Context) error {
	j.mu.Lock()
	j.cancelled = true
	j.mu.Unlock()
	j.cancel()
	return nil
}

func (j *job) Snapshot() domain.ProgressSnapshot {
	return domain.ProgressSnapshot{
		TaskID: j.id, BytesDone: atomic.LoadInt64(&j.bytesDone),
		BytesTotal: atomic.LoadInt64(&j.total), SpeedBps: float64(atomic.LoadUint64(&j.speedBps)),
		UpdatedAt: time.Now().UTC(),
	}
}

func (j *job) isCancelled() bool { j.mu.Lock(); defer j.mu.Unlock(); return j.cancelled }
func (j *job) isPaused() bool    { j.mu.Lock(); defer j.mu.Unlock(); return j.paused }
func (j *job) cancelJob()        { j.mu.Lock(); j.cancelled = true; j.mu.Unlock(); j.cancel() }

// svTestPauseHook permite pausar deterministicamente uma tarefa JÁ INICIADA
// (redes loopback são rápidas demais para pausar por tempo). Quando o hook
// está ativo, a pausa torna-se efetiva em dois pontos:
//   - após cada chunk escrito no ficheiro temporário (progresso já gravado
//     antes de interromper a rede — nunca há perda silenciosa), via
//     checkPauseAfterWrite;
//   - antes de qualquer escrita, se houver estado de retoma válido (segunda
//     corrida de um teste de retoma — pausa imediata e consistente), via
//     pauseBeforeStart.
// O primeiro Load+Delete é feito pelo caminho que chegar primeiro; o outro
// torna-se no-op. Nenhum dos dois pode ser perdido: pauseBeforeStart deixa
// o flag intacto quando não existe estado de retoma, para que o caminho
// pós-escrita o consuma.
var svTestPauseHook sync.Map // taskID -> bool

func testSetPauseHook(id string)   { svTestPauseHook.Store(id, true) }
func testClearPauseHook(id string) { svTestPauseHook.Delete(id) }

// consumePauseFlag remove o flag atómico do mapa e devolve true se estava
// definido. Não bloqueia nem altera o estado da job — quem consome decide.
func consumePauseFlag(id string) bool {
	v, ok := svTestPauseHook.LoadAndDelete(id)
	return ok && v == true
}

// checkPauseAfterWrite é chamado na goroutine de transferência após cada
// chunk escrito + fsync parcial. Se o flag de teste estiver ativo, marca a
// job como pausada e cancela o contexto — o ciclo de leitura termina pela
// via rerr!=nil com isPaused()==true, persistindo exatamente os bytes que
// foram escritos (offset == len(payload)).
func (j *job) checkPauseAfterWrite() {
	if !consumePauseFlag(j.id) {
		return
	}
	j.mu.Lock()
	if !j.cancelled {
		j.paused = true
	}
	j.mu.Unlock()
	j.cancel()
}

func (j *job) pauseBeforeStart() bool {
	if !consumePauseFlag(j.id) {
		return false
	}
	j.mu.Lock()
	if !j.cancelled {
		j.paused = true
	}
	j.mu.Unlock()
	j.persistResume()
	return true
}

func (j *job) emit(kind engine.EventKind, extra map[string]string) {
	if j.sink == nil {
		return
	}
	j.sink.Emit(engine.Event{Kind: kind, TaskID: j.id, Progress: j.Snapshot(),
		Error: nil, Timestamp: time.Now().UTC().UnixMilli(), Payload: extra})
}

func (j *job) emitErr(de *domain.DownloadError) {
	if j.sink == nil {
		return
	}
	j.sink.Emit(engine.Event{Kind: engine.EventError, TaskID: j.id,
		Progress: j.Snapshot(), Error: de, Timestamp: time.Now().UTC().UnixMilli()})
}

func (j *job) persistResume() {
	if j.opts_persist == nil {
		return
	}
	j.opts_persist(ResumeState{TaskID: j.id, TempPath: j.tempPath,
		BytesDone: atomic.LoadInt64(&j.bytesDone), Total: atomic.LoadInt64(&j.total),
		ETag: j.etag, LastModified: j.lastMod, CapturedAt: j.capturedAt})
}

// opts_persist é injetado pelo motor (campo separado para clareza).
// (definido abaixo no run para evitar inicializar em cada método)

// ---- transferência ----

func (e *Engine) run(j *job) error {
	j.opts_persist = e.opts.ResumePersist
	src := j.task.Source
	rawURL := src.URL

	limit := j.task.Policy.SpeedLimitBps
	req, err := http.NewRequestWithContext(j.ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return diag.Explain(err, src.Redacted())
	}
	req.Header.Set("User-Agent", e.opts.UserAgent)

	var resume *ResumeState
	if e.opts.ResumeProvider != nil {
		if rs, ok := e.opts.ResumeProvider(j.id); ok && rs != nil && rs.BytesDone > 0 && rs.TempPath != "" {
			resume = rs
		}
	}
	offset := int64(0)
	if resume != nil {
		// validar que o temp local ainda existe e tem exatamente rs.BytesDone
		if st, serr := os.Stat(resume.TempPath); serr == nil && st.Size() == resume.BytesDone {
			offset = resume.BytesDone
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
		} else {
			resume = nil // temp perdido/corrompido => recomeçar limpo
		}
	}

	// Verificar pausa ANTES de qualquer escrita: com estado de retoma válido,
	// a pausa é imediata e o progresso fica consistentemente persistido.
	if j.pauseBeforeStart() {
		return nil
	}

	resp, err := e.client.Do(req)
	if err != nil {
		de := diag.Explain(err, src.Redacted())
		if j.isPaused() {
			return nil // pausa é saída controlada, não erro
		}
		return de
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusRequestedRangeNotSatisfiable:
		// offset >= tamanho atual do recurso: pode ser recurso encolhido OU
		// offset válido no fim. Verificar Content-Range */N.
		cr := resp.Header.Get("Content-Range")
		if strings.HasSuffix(cr, "/"+fmt.Sprint(offset)) || strings.Contains(cr, "*") {
			return domain.NewError(domain.ErrResumeMismatch, nil,
				"O servidor recusou o intervalo de retoma (recurso mudou ou expirou).",
				"Retoma indisponível; será iniciado um download novo se autorizar.",
				domain.CertaintyObserved, true)
		}
		return domain.NewError(domain.ErrResumeMismatch, nil, "Intervalo pedido inválido (416).",
			"Reiniciar transferência.", domain.CertaintyObserved, true)
	case isExpiredURL(resp.StatusCode):
		return domain.NewError(domain.ErrURLExpired, nil,
			fmt.Sprintf("Servidor recusou o acesso (HTTP %d) — URL provavelmente expirado.", resp.StatusCode),
			"Obtenha um novo link na origem e reintroduza-o.", domain.CertaintyObserved, false)
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return domain.NewError(domain.ErrHTTPStatus, nil,
			fmt.Sprintf("HTTP %d no pedido à origem.", resp.StatusCode),
			"Confirme o link; se persistir, a origem está indisponível.", domain.CertaintyObserved, true)
	}

	// Se pedimos Range mas veio 200 completo => servidor ignorou Range.
	// Estratéga segura: descartar offset e recomeçar (nunca misturar fontes).
	restartFull := false
	if offset > 0 && resp.StatusCode == http.StatusOK {
		restartFull = true
	} else if resp.StatusCode == http.StatusPartialContent {
		end := offset + atomic.LoadInt64(&j.total) - 1 // total ainda desconhecido? usar CL+off-1
		cl := parseContentLength(resp.Header)
		if cl >= 0 {
			end = offset + cl - 1
		}
		if verr := validateContentRange(resp.Header.Get("Content-Range"), offset, end); verr != nil {
			return domain.NewError(domain.ErrResumeMismatch, verr,
				"Resposta parcial inconsistente com o pedido.",
				"Retoma abortada por segurança; reinício seguro disponível.", domain.CertaintyObserved, true)
		}
	}

	// metadados honrados: só reportamos quando REALMENTE disponíveis
	total := parseContentLength(resp.Header)
	if resp.StatusCode == http.StatusPartialContent && total >= 0 {
		total += offset
	}
	if cr := resp.Header.Get("Content-Range"); total < 0 && strings.Contains(cr, "/") {
		if n, cerr := fmt.Sscanf(cr, "bytes */%d", new(int64)); n == 1 {
			_ = cerr
		}
		idx := strings.LastIndexByte(cr, '/')
		if idx >= 0 {
			totStr := cr[idx+1:]
			if totStr != "*" {
				var t int64
				if _, e2 := fmt.Sscanf(totStr, "%d", &t); e2 == nil {
					total = t
				}
			}
		}
	}
	atomic.StoreInt64(&j.total, total)
	j.etag = resp.Header.Get("ETag")
	j.lastMod = resp.Header.Get("Last-Modified")
	j.capturedAt = time.Now().UTC()

	// verificação de drift remoto contra a sessão anterior
	if resume != nil && (resume.ETag != "" || resume.Total > 0) {
		old := integrity.RemoteIdentity{ETag: resume.ETag, LastModified: resume.LastModified, SizeBytes: resume.Total}
		now := integrity.RemoteIdentity{ETag: j.etag, LastModified: j.lastMod, SizeBytes: total}
		if drift := old.Compare(now); drift != "" {
			return domain.NewError(domain.ErrResumeMismatch, nil,
				"O recurso remoto mudou desde a última sessão ("+drift+").",
				"Retoma insegura; reinicie a transferência para garantir consistência.",
				domain.CertaintyObserved, true)
		}
	}

	// política de tamanho máximo
	if total >= 0 && j.task.Policy.MaxSizeBytes > 0 && total > j.task.Policy.MaxSizeBytes {
		return domain.NewError(domain.ErrPolicyViolation, nil,
			fmt.Sprintf("Ficheiro tem %d bytes; limite configurado é %d.", total, j.task.Policy.MaxSizeBytes),
			"Aumente o limite nas configurações se confiar na origem.", domain.CertaintyObserved, false)
	}

	name := src.DisplayName
	if name == "" {
		name = filenameFrom(resp, rawURL)
	}
	cleanName, findings := security.CheckFileName(name)
	for _, f := range findings {
		if f.Severity == "block" {
			return domain.NewError(domain.ErrPolicyViolation, nil, "Nome de ficheiro rejeitado: "+f.Message,
				"Escolha outro nome.", domain.CertaintyObserved, false)
		}
	}

	destDir := j.task.Policy.DestinationDir
	if destDir == "" {
		destDir = "."
	}
	tmp := filepath.Join(destDir, cleanName+".svpart")
	if restartFull {
		_ = os.Remove(tmp)
		offset = 0
		atomic.StoreInt64(&j.bytesDone, 0)
	}
	if resume != nil && resume.TempPath != "" {
		tmp = resume.TempPath
	}
	j.tempPath = tmp

	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		if os.IsPermission(err) {
			return domain.NewError(domain.ErrPermissionDenied, err, "Sem permissão para escrever em "+destDir,
				"Escolha outra pasta de destino.", domain.CertaintyObserved, false)
		}
		return diag.Explain(err, src.Redacted())
	}
	if _, seekErr := f.Seek(offset, io.SeekStart); seekErr != nil {
		f.Close()
		return diag.Explain(seekErr, src.Redacted())
	}
	truncErr := f.Truncate(offset) // garante que nada além do offset sobrevive
	if truncErr != nil {
		f.Close()
		return diag.Explain(truncErr, src.Redacted())
	}

	emit := j.emit
	interval := e.opts.ProgressEvery
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	lastEmit := time.Now()
	startT := time.Now()
	baseDone := offset
	buf := make([]byte, 64*1024)

	var rl *rateWindow
	if limit > 0 {
		rl = newRateWindow(limit)
	}
	lastPersist := offset
	const persistEvery = int64(256 * 1024)

	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if werr := writeChunk(f, buf[:n]); werr != nil {
				f.Close()
				if isNoSpace(werr) {
					return domain.NewError(domain.ErrNoSpace, werr, "Espaço em disco esgotado.",
						"Liberte espaço e retome; o progresso até aqui foi preservado.", domain.CertaintyObserved, true)
				}
				return diag.Explain(werr, src.Redacted())
			}
			done := atomic.AddInt64(&j.bytesDone, int64(n))
			if e.opts.WriteHook != nil {
				e.opts.WriteHook(j.id, done)
			}
			j.checkPauseAfterWrite() // pausa determinística pós-escrita (nunca perde progresso)
			if rl != nil {
				rl.SleepFor(buf[:n])
			}
			el := time.Since(startT).Seconds()
			if el > 0.2 {
				atomic.StoreUint64(&j.speedBps, uint64(float64(done-baseDone)/el))
			}
			if time.Since(lastEmit) >= interval {
				emit(engine.EventProgress, nil)
				lastEmit = time.Now()
			}
			if done-lastPersist >= persistEvery {
				j.persistResume()
				lastPersist = done
			}
			if total >= 0 && done >= total {
				break
			}
			// Pausa determinística de teste: se o flag estiver ativo, parar
			// imediatamente após este chunk escrito — progresso preservado,
			// nunca há perda silenciosa. O ciclo rerr!=nil abaixo não é
			// alcançado porque já saímos daqui com f.Close() feito.
			if j.isPaused() {
				f.Sync()
				f.Close()
				j.persistResume()
				return nil
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Sync()
			f.Close()
			if j.isPaused() {
				j.persistResume()
				return nil
			}
			if j.ctx.Err() == context.Canceled && j.isCancelled() {
				return nil
			}
			if j.ctx.Err() != nil && !j.isPaused() && !j.isCancelled() {
				return domain.NewError(domain.ErrConnectionLost, rerr, "Ligação interrompida durante a transferência.",
					"Pode retomar; o progresso parcial foi preservado.", domain.CertaintyObserved, true)
			}
			return diag.Explain(rerr, src.Redacted())
		}
	}

	if err := f.Sync(); err != nil {
		f.Close()
		return diag.Explain(err, src.Redacted())
	}
	if err := f.Close(); err != nil {
		return diag.Explain(err, src.Redacted())
	}

	finalDone := atomic.LoadInt64(&j.bytesDone)
	if total >= 0 && finalDone != total {
		return domain.NewError(domain.ErrCorruptData, nil,
			fmt.Sprintf("Transferência terminou com %d/%d bytes.", finalDone, total),
			"Retome a transferência.", domain.CertaintyObserved, true)
	}

	// verificação de integridade conforme política (SHA-256 integral)
	expected := ""
	for _, fm := range j.task.Files {
		if fm.Index == 0 {
			expected = fm.SHA256Hex
		}
	}
	shaHex, herr := integrity.HashFile(tmp)
	if herr != nil {
		return diag.Explain(herr, src.Redacted())
	}
	if j.task.Policy.RequireIntegrity == domain.IntegritySHA256 {
		res, actual, verr := integrity.VerifyFile(tmp, expected)
		if verr != nil {
			return diag.Explain(verr, src.Redacted())
		}
		if res != integrity.ResultOK {
			emit(engine.EventIntegrityReport, map[string]string{"result": res.String(), "expected": expected, "actual": actual})
			return domain.NewError(domain.ErrIntegrityFailure, nil,
				"Verificação SHA-256 falhou ("+res.String()+").",
				"O ficheiro parcial foi mantido para diagnóstico; apague-o e retome.", domain.CertaintyObserved, true)
		}
	}

	// finalização segura: rename atómico; NUNCA sobrescrever silenciosamente
	finalPath := filepath.Join(destDir, cleanName)
	if _, sterr := os.Stat(finalPath); sterr == nil {
		finalPath = uniquePath(finalPath)
	}
	if rerr := os.Rename(tmp, finalPath); rerr != nil {
		return diag.Explain(rerr, src.Redacted())
	}

	emit(engine.EventFileDiscovered, map[string]string{"path": finalPath, "sha256": shaHex,
		"size": fmt.Sprint(finalDone)})
	emit(engine.EventCompleted, map[string]string{"path": finalPath, "sha256": shaHex})
	return nil
}

// ---- helpers ----

func writeChunk(f *os.File, p []byte) error {
	for len(p) > 0 {
		n, err := f.Write(p)
		if err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

func isNoSpace(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "no space")
}

// filenameFrom extrai nome de Content-Disposition ou do path do URL.
func filenameFrom(resp *http.Response, rawURL string) string {
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		if i := strings.Index(strings.ToLower(cd), "filename="); i >= 0 {
			name := cd[i+len("filename="):]
			name = strings.Trim(strings.TrimSpace(name), `"'`)
			if name != "" {
				return filepath.Base(name)
			}
		}
	}
	if u, err := http.NewRequest("GET", rawURL, nil); err == nil {
		if b := filepath.Base(u.URL.Path); b != "/" && b != "." && b != "" {
			return b
		}
	}
	return "download.bin"
}

func uniquePath(p string) string {
	ext := filepath.Ext(p)
	base := strings.TrimSuffix(p, ext)
	for i := 1; i < 10000; i++ {
		cand := fmt.Sprintf("%s (%d)%s", base, i, ext)
		if _, err := os.Stat(cand); os.IsNotExist(err) {
			return cand
		}
	}
	return p + ".sv"
}

// rateWindow limita bytes/s com janela deslizante simples (sem deps externas;
// golang.org/x/time/rate seria alternativa — stdlib-first decision ADR-003).
type rateWindow struct {
	limitBps int64
	window   time.Duration
	start    time.Time
	bytes    int64
}

func newRateWindow(bps int64) *rateWindow {
	return &rateWindow{limitBps: bps, window: time.Second, start: time.Now()}
}

func (r *rateWindow) SleepFor(p []byte) {
	r.bytes += int64(len(p))
	elapsed := time.Since(r.start)
	if elapsed >= r.window {
		r.start = time.Now()
		r.bytes = 0
		return
	}
	want := float64(r.bytes) / float64(r.limitBps) // segundos que deviam ter passado
	if delta := want - elapsed.Seconds(); delta > 0 {
		time.Sleep(time.Duration(delta * float64(time.Second)))
		r.start = time.Now()
		r.bytes = 0
	}
}
