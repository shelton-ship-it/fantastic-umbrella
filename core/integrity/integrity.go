// Package integrity fornece hashing SHA-256 em streaming (sem leituras
// integrais repetidas), comparação de identificadores remotos e relatórios
// verificáveis. Distinção honesta: hash local deteta CORRUPÇÃO LOCAL; não
// recupera blocos de um servidor sem suporte a Range ou fonte alternativa.
package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"
)

// HashFile calcula SHA-256 em streaming com buffer grande (1 MiB).
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("integrity: abrir %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 1<<20)
	if _, err := io.CopyBuffer(h, f, buf); err != nil {
		return "", fmt.Errorf("integrity: ler %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Result é o veredicto de integridade de uma tarefa/ficheiro.
type Result int

const (
	ResultOK Result = iota
	ResultMismatch
	ResultMissingExpected // origem não forneceu hash — NÃO afirmar "verificado"
	ResultIOError
)

func (r Result) String() string {
	switch r {
	case ResultOK:
		return "ok"
	case ResultMismatch:
		return "mismatch"
	case ResultMissingExpected:
		return "missing_expected_hash"
	}
	return "io_error"
}

// VerifyFile compara o hash do ficheiro com o esperado.
func VerifyFile(filePath, expectedHex string) (Result, string, error) {
	if expectedHex == "" {
		return ResultMissingExpected, "", nil
	}
	actual, err := HashFile(filePath)
	if err != nil {
		return ResultIOError, "", err
	}
	if actual == lower(expectedHex) {
		return ResultOK, actual, nil
	}
	return ResultMismatch, actual, nil
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}

// RemoteIdentity captura identificadores estáveis do recurso remoto para
// distinguir "servidor mudou o ficheiro" de "o nosso download corrompeu".
type RemoteIdentity struct {
	ETag         string
	LastModified string
	SizeBytes    int64
	CapturedAt   time.Time
}

// Compare devolve vazio se compatível, ou descrição da divergência.
func (old RemoteIdentity) Compare(now RemoteIdentity) string {
	var diffs []string
	if old.ETag != "" && now.ETag != "" && old.ETag != now.ETag {
		diffs = append(diffs, "ETag alterado")
	}
	if old.SizeBytes > 0 && now.SizeBytes > 0 && old.SizeBytes != now.SizeBytes {
		diffs = append(diffs, fmt.Sprintf("tamanho alterado (%d -> %d)", old.SizeBytes, now.SizeBytes))
	}
	if old.LastModified != "" && now.LastModified != "" && old.LastModified != now.LastModified {
		diffs = append(diffs, "Last-Modified alterado")
	}
	if len(diffs) == 0 {
		return ""
	}
	return join(diffs, "; ")
}

func join(parts []string, sep string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += sep
		}
		out += p
	}
	return out
}

// Report é um relatório de integridade assinável/auditável (Fase 7 o assina
// com chave do dispositivo quando existir keystore; aqui fica o formato).
type Report struct {
	TaskID      string       `json:"task_id"`
	Files       []FileReport `json:"files"`
	GeneratedAt time.Time    `json:"generated_at"`
	CoreVersion string       `json:"core_version"`
}

type FileReport struct {
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	SizeBytes   int64  `json:"size_bytes"`
	Result      string `json:"result"` // ok | mismatch | missing_expected_hash
	RemoteDrift string `json:"remote_drift,omitempty"`
}
