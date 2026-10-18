package domain

import "fmt"

// ErrorClass classifica diagnosticamente um erro para as camadas de UI/observabilidade.
// O diagnóstico deve explicar causa conhecida, grau de certeza e ação recomendada.
type ErrorClass int

const (
	ErrUnknown ErrorClass = iota
	ErrDNS
	ErrTLS
	ErrConnectionLost
	ErrHTTPStatus
	ErrURLExpired
	ErrNoSpace
	ErrPermissionDenied
	ErrResumeUnsupported
	ErrResumeMismatch    // recurso remoto mudou entre sessões (tamanho/ETag)
	ErrIntegrityFailure  // hash/bloco não corresponde
	ErrCorruptData       // dados locais corrompidos
	ErrResourceExhausted // limites de CPU/memória/disco/ligação
	ErrInvalidInput      // URL/magnet/torrent malformado
	ErrUnsupportedSource // origem sem adaptador — comunicar limitação, não improvisar
	ErrPolicyViolation   // bloqueio de segurança (SSRF, path traversal, DRM...)
	ErrLicenseInvalid
)

func (c ErrorClass) String() string {
	names := [...]string{"unknown", "dns", "tls", "connection_lost", "http_status",
		"url_expired", "no_space", "permission_denied", "resume_unsupported",
		"resume_mismatch", "integrity_failure", "corrupt_data", "resource_exhausted",
		"invalid_input", "unsupported_source", "policy_violation", "license_invalid"}
	if int(c) < len(names) {
		return names[c]
	}
	return "unknown"
}

// Certainty expressa honestamente o grau de confiança no diagnóstico.
type Certainty int

const (
	CertaintyHeuristic Certainty = iota // heurística
	CertaintyObserved                   // evidência direta (código HTTP, errno, hash mismatch)
)

func (c Certainty) String() string {
	if c == CertaintyObserved {
		return "observed"
	}
	return "heuristic"
}

// DownloadError é o erro tipado do domínio. Nunca transporta tokens, cookies
// ou URLs sensíveis completos — use RedactedMessage para exibição/logs.
type DownloadError struct {
	Class      ErrorClass
	Cause      error
	Message    string // mensagem humana, já redigida
	Action     string // ação recomendada ao utilizador
	Certainty  Certainty
	RemoteCode int               // código HTTP quando aplicável
	Retryable  bool              // retoma automática faz sentido?
	Context    map[string]string // metadados seguros p/ diagnósticos
}

func (e *DownloadError) Error() string {
	return fmt.Sprintf("%s: %s", e.Class, e.Message)
}

func (e *DownloadError) Unwrap() error { return e.Cause }

// NewError constrói um erro tipado com todos os campos de diagnóstico.
func NewError(class ErrorClass, cause error, msg, action string, cert Certainty, retryable bool) *DownloadError {
	return &DownloadError{Class: class, Cause: cause, Message: msg, Action: action, Certainty: cert, Retryable: retryable}
}

// IsClass permite testes e decisões de política por classe.
func IsClass(err error, class ErrorClass) bool {
	de, ok := err.(*DownloadError)
	return ok && de.Class == class
}
