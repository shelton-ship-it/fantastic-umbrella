package domain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// DownloadErrorJSON é a forma serializável de DownloadError. Cause (erro Go
// vivo, possivelmente com strings sensíveis do sistema) NÃO é persistido —
// apenas Class/Message/Certainty/RemoteCode/Retryable/Context, que já são
// mensagens humanas redigidas. Reconstrói-se *DownloadError via ToErr.
type DownloadErrorJSON struct {
	Class      ErrorClass        `json:"class"`
	Message    string            `json:"message"`
	Action     string            `json:"action"`
	Certainty  Certainty         `json:"certainty"`
	RemoteCode int               `json:"remote_code,omitempty"`
	Retryable  bool              `json:"retryable"`
	Context    map[string]string `json:"context,omitempty"`
}

func (e *DownloadError) ToJSON() DownloadErrorJSON {
	if e == nil {
		return DownloadErrorJSON{}
	}
	return DownloadErrorJSON{
		Class: e.Class, Message: e.Message, Action: e.Action,
		Certainty: e.Certainty, RemoteCode: e.RemoteCode,
		Retryable: e.Retryable, Context: e.Context,
	}
}

func (j DownloadErrorJSON) ToErr() *DownloadError {
	if j.Class == ErrUnknown && j.Message == "" {
		return nil // erro ausente
	}
	return &DownloadError{
		Class: j.Class, Message: j.Message, Action: j.Action,
		Certainty: j.Certainty, RemoteCode: j.RemoteCode,
		Retryable: j.Retryable, Context: j.Context,
	}
}

// taskWire separa o que vai a disco do runtime não serializável.
// Version (optimistic concurrency) vive na coluna própria da tabela, não no blob.
type taskWire struct {
	ID        string             `json:"id"`
	Source    DownloadSource     `json:"source"`
	Policy    DownloadPolicy     `json:"policy"`
	State     State              `json:"state"`
	Progress  ProgressSnapshot   `json:"progress"`
	Error     *DownloadErrorJSON `json:"error,omitempty"`
	Files     []FileMetadata     `json:"files,omitempty"`
	CreatedAt int64              `json:"created_at_ms"`
	UpdatedAt int64              `json:"updated_at_ms"`
	Priority  int                `json:"priority"`
}

// MarshalTask serializa uma tarefa para persistência (blob JSON canónico).
func MarshalTask(t *DownloadTask) ([]byte, error) {
	w := taskWire{
		ID: t.ID, Source: t.Source, Policy: t.Policy, State: t.State,
		Progress: t.Progress, Files: t.Files, Priority: t.Priority,
		CreatedAt: t.CreatedAt.UnixMilli(), UpdatedAt: t.UpdatedAt.UnixMilli(),
	}
	if t.Error != nil {
		e := t.Error.ToJSON()
		w.Error = &e
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(w); err != nil {
		return nil, fmt.Errorf("domain: marshal task %s: %w", t.ID, err)
	}
	return buf.Bytes(), nil
}

// UnmarshalTask desserializa com validação estrita: campos desconhecidos são
// recusados (formato futuro ≠ presente; schema em migrations/storage).
func UnmarshalTask(data []byte) (*DownloadTask, error) {
	var w taskWire
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("domain: unmarshal task: %w", err)
	}
	if w.ID == "" {
		return nil, fmt.Errorf("domain: task sem id")
	}
	if int(w.State) < 0 || int(w.State) > int(StateCancelled) {
		return nil, fmt.Errorf("domain: task %s estado inválido %d", w.ID, int(w.State))
	}
	t := &DownloadTask{
		ID: w.ID, Source: w.Source, Policy: w.Policy, State: w.State,
		Progress: w.Progress, Files: w.Files, Priority: w.Priority,
		CreatedAt: msTime(w.CreatedAt), UpdatedAt: msTime(w.UpdatedAt),
	}
	if w.Error != nil {
		t.Error = w.Error.ToErr()
	}
	return t, nil
}

func msTime(ms int64) time.Time { return time.UnixMilli(ms).UTC() }
