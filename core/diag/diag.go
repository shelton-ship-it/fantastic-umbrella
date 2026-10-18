// Package diag traduz erros de baixo nível em diagnósticos humanos com causa,
// grau de certeza e ação recomendada. Os registos NUNCA contêm tokens,
// cookies, credenciais ou URLs completas por defeito (redação aplicada aqui).
package diag

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"strings"
	"syscall"

	"streamvault/core/domain"
)

// Explain classifica um erro cru da stdlib num DownloadError tipado.
// Heurísticas são marcadas como CertaintyHeuristic; errno/códigos diretos
// como CertaintyObserved — honestidade sobre o que realmente se sabe.
func Explain(err error, sourceRedacted string) *domain.DownloadError {
	if err == nil {
		return nil
	}
	if de, ok := err.(*domain.DownloadError); ok {
		return de // já classificado a montante
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return domain.NewError(domain.ErrDNS, err,
			fmt.Sprintf("Falha de resolução DNS para %s.", redactHost(dnsErr.Name)),
			"Verifique a ligação à Internet; se persistir, tente outra rede DNS.",
			domain.CertaintyObserved, true)
	}
	var certHostErr x509.HostnameError
	var certUnknown x509.UnknownAuthorityError
	var certInvalid x509.CertificateInvalidError
	if errors.As(err, &certHostErr) || errors.As(err, &certUnknown) || errors.As(err, &certInvalid) ||
		strings.Contains(strings.ToLower(err.Error()), "x509") {
		return domain.NewError(domain.ErrTLS, err,
			"A validação do certificado TLS falhou.",
			"Não desative a validação de certificados. Confirme se a data/hora do sistema está correta e se o site usa certificado válido.",
			domain.CertaintyObserved, false)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return domain.NewError(domain.ErrConnectionLost, err,
			"A ligação expirou durante a transferência.",
			"A retoma será tentada automaticamente quando disponível.",
			domain.CertaintyObserved, true)
	}
	if isConnReset(err) {
		return domain.NewError(domain.ErrConnectionLost, err,
			"A ligação foi interrompida pelo servidor remoto.",
			"Nova tentativa será agendada; se repetir, o servidor pode estar a limitar ligações.",
			domain.CertaintyObserved, true)
	}
	if errors.Is(err, syscall.ENOSPC) {
		return domain.NewError(domain.ErrNoSpace, err,
			"O disco está cheio.",
			"Liberte espaço no volume de destino antes de retomar.",
			domain.CertaintyObserved, false)
	}
	if errors.Is(err, syscall.EACCES) || errors.Is(err, fs.ErrPermission) || os.IsPermission(err) {
		return domain.NewError(domain.ErrPermissionDenied, err,
			"Sem permissão para escrever no destino.",
			"Escolha uma pasta com permissões de escrita ou conceda-as ao sistema de ficheiros.",
			domain.CertaintyObserved, false)
	}
	return domain.NewError(domain.ErrUnknown, err,
		"Falha não classificada junto de "+sourceRedacted+".",
		"Consulte os detalhes técnicos no registo de diagnóstico.",
		domain.CertaintyHeuristic, true)
}

func isConnReset(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "broken pipe") ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED)
}

// redactHost mantém só o domínio de segundo nível nos logs de DNS.
func redactHost(h string) string {
	parts := strings.Split(h, ".")
	if len(parts) <= 2 {
		return h
	}
	return "…." + strings.Join(parts[len(parts)-2:], ".")
}

// RedactURL remove query strings (tokens assinados) de qualquer mensagem.
func RedactURL(u string) string {
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		return u[:i] + "?…"
	}
	return u
}
