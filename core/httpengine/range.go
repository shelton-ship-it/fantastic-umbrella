package httpengine

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// rangeSupport descreve o que sabemos sobre suporte a Range do servidor —
// com honestidade sobre como foi obtido (briefing: nunca assumir HEAD/GET).
type rangeSupport int

const (
	rangeUnknown     rangeSupport = iota
	rangeSupported                // Accept-Ranges: bytes observado
	rangeUnsupported              // Accept-Ranges: none observado
	rangeProbedOK                 // GET parcial 206 validado por Content-Range
	rangeProbedFail               // pedido parcial devolveu 200 inteiro => sem retoma segura
)

func detectRangeSupport(h http.Header) rangeSupport {
	v := strings.ToLower(strings.TrimSpace(h.Get("Accept-Ranges")))
	switch {
	case v == "bytes":
		return rangeSupported
	case v == "none":
		return rangeUnsupported
	default:
		return rangeUnknown
	}
}

// validateContentRange confirma que um corpo 206 corresponde EXATAMENTE ao
// intervalo pedido. Um Content-Range ausente/errado num 206 é tratado como
// recurso não confiável (servidores mal implementados): recusamos retoma.
func validateContentRange(header string, start, end int64) error {
	if header == "" {
		return fmt.Errorf("resposta 206 sem Content-Range")
	}
	i := strings.IndexByte(header, ' ')
	if i < 0 || !strings.EqualFold(header[:i], "bytes") {
		return fmt.Errorf("Content-Range malformado: %q", header)
	}
	rest := strings.TrimSpace(header[i+1:])
	slash := strings.LastIndexByte(rest, '/')
	if slash < 0 {
		return fmt.Errorf("Content-Range sem total: %q", header)
	}
	totalStr := rest[slash+1:]
	if totalStr != "*" {
		t, err := strconv.ParseInt(totalStr, 10, 64)
		if err != nil || t < 0 {
			return fmt.Errorf("Content-Range total inválido: %q", header)
		}
	}
	se := strings.SplitN(rest[:slash], "-", 2)
	if len(se) != 2 {
		return fmt.Errorf("Content-Range intervalo inválido: %q", header)
	}
	s, err1 := strconv.ParseInt(strings.TrimSpace(se[0]), 10, 64)
	e, err2 := strconv.ParseInt(strings.TrimSpace(se[1]), 10, 64)
	if err1 != nil || err2 != nil {
		return fmt.Errorf("Content-Range números inválidos: %q", header)
	}
	if s != start || e != end {
		return fmt.Errorf("Content-Range %d-%d não corresponde ao pedido %d-%d", s, e, start, end)
	}
	return nil
}

// parseContentLength lê Content-Length; -1 quando ausente/inválido.
func parseContentLength(h http.Header) int64 {
	v := h.Get("Content-Length")
	if v == "" {
		return -1
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return -1
	}
	return n
}

// isExpiredURL reporta códigos que indicam link assinado expirado/recusado.
// Conservador: só evidência HTTP direta, nada de adivinhação.
func isExpiredURL(status int) bool {
	return status == http.StatusForbidden || status == http.StatusUnauthorized || status == http.StatusGone
}
