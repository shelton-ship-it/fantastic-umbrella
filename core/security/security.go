// Package security analisa URLs e caminhos ANTES de qualquer transferência.
// Verificações proporcionais ao risco: esquema, host (SSRF), traversal,
// extensões perigosas e limites absolutos de recursos.
package security

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// Options controla o rigor; apps podem apertar, nunca afrouxar abaixo do mínimo.
type Options struct {
	// AllowPrivateNetworks: FALSO por defeito. Um produto de downloads no
	// dispositivo não tem razão legítima para descarregar de 127.0.0.1,
	// 169.254.169.254 (metadados cloud), RFC1918 etc. Se uma origem local
	// for intencional (NAS do utilizador), a UI pede confirmação explícita.
	AllowPrivateNetworks bool
	// AllowedSchemes adicional; http/https/magnet/file já são tratados.
	MaxURLLength int // 0 => default 4096
}

func DefaultOptions() Options {
	return Options{AllowPrivateNetworks: false, MaxURLLength: 4096}
}

// Finding descreve um problema com severidade e explicação humana.
type Finding struct {
	Severity string // "block" | "warn"
	Code     string
	Message  string
}

// CheckURL valida sintaxe + política de segurança de uma URL de download.
func CheckURL(raw string, opts Options) []Finding {
	var f []Finding
	if opts.MaxURLLength == 0 {
		opts.MaxURLLength = 4096
	}
	if len(raw) > opts.MaxURLLength {
		f = append(f, Finding{"block", "url_too_long", "URL excede o limite seguro de comprimento."})
		return f
	}
	u, err := url.Parse(raw)
	if err != nil {
		f = append(f, Finding{"block", "url_invalid", "URL não pode ser interpretada."})
		return f
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "magnet":
		// ok
	case "ftp", "file", "telnet", "ssh", "sftp":
		f = append(f, Finding{"block", "scheme_unsupported",
			fmt.Sprintf("Esquema %q não é suportado pelo motor; use HTTP(S), magnet ou ficheiro .torrent local.", u.Scheme)})
		return f
	default:
		f = append(f, Finding{"block", "scheme_dangerous",
			fmt.Sprintf("Esquema %q recusado — pode executar ações no sistema em vez de transferir dados.", u.Scheme)})
		return f
	}
	if u.Scheme == "magnet" {
		return f // validação profunda de campos é do linkrec
	}
	if u.Host == "" {
		f = append(f, Finding{"block", "host_missing", "URL sem host."})
		return f
	}
	if u.User != nil {
		f = append(f, Finding{"warn", "credentials_in_url",
			"A URL contém utilizador/senha embutidos; prefira autenticação própria do cliente."})
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if bad, why := privateIP(ip); bad && !opts.AllowPrivateNetworks {
			f = append(f, Finding{"block", "ssrf_private_ip",
				"Destino aponta para rede local/" + why + "; bloqueado para proteger serviços internos do dispositivo."})
		}
	} else if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".local") ||
		strings.HasSuffix(strings.ToLower(host), ".internal") || strings.HasSuffix(strings.ToLower(host), ".metadata") {
		if !opts.AllowPrivateNetworks {
			f = append(f, Finding{"block", "ssrf_private_name",
				"Nome de host resolve tipicamente para serviços locais/metadados; recuse se não for intencional."})
		}
	}
	return f
}

func privateIP(ip net.IP) (bool, string) {
	if ip.IsLoopback() {
		return true, "loopback"
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true, "link-local (inclui 169.254.169.254 — metadados de cloud)"
	}
	if ip.IsPrivate() {
		return true, "rede privada"
	}
	if ip.IsUnspecified() {
		return true, "endereço não especificado"
	}
	return false, ""
}

// dangerousExtensions: executáveis/escritas que NÃO devem ser iniciadas nem
// abertas automaticamente após download. O download em si pode ser permitido
// com aviso — a proibição é sobre EXECUÇÃO automática (princípio global #9).
var dangerousRe = regexp.MustCompile(`(?i)\.(exe|scr|msi|msp|com|pif|cmd|bat|vb|vbs|js|jse|wsf|ps1|jar|apk|sh|desktop|reg|lnk)$`)

// CheckFileName valida um nome/caminho proposto contra traversal e extensões
// sensíveis. Retorna caminho limpo OU finding de bloqueio.
func CheckFileName(name string) (clean string, findings []Finding) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", []Finding{{"block", "name_empty", "Nome de ficheiro vazio."}}
	}
	if len(name) > 255 {
		return "", []Finding{{"block", "name_too_long", "Nome de ficheiro demasiado longo."}}
	}
	if strings.ContainsAny(name, "\x00") {
		return "", []Finding{{"block", "name_nul_byte", "Nome contém byte nulo."}}
	}
	slashed := filepath.ToSlash(name)
	// Detetar segmentos ".." LITERAIS antes de path.Clean os colapsar —
	// Clean("/../../etc/x") devolve "/etc/x" e mascarraria a tentativa.
	for _, seg := range strings.Split(slashed, "/") {
		if seg == ".." {
			return "", []Finding{{"block", "path_traversal", "Nome tenta escapar da pasta destino (path traversal)."}}
		}
	}
	clean = strings.TrimPrefix(path.Clean("/"+slashed), "/")
	if clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
		return "", []Finding{{"block", "path_traversal", "Nome tenta escapar da pasta destino (path traversal)."}}
	}
	if filepath.IsAbs(name) || regexp.MustCompile(`(?i)^[a-z]:[\\/ ]`).MatchString(name) {
		return "", []Finding{{"block", "absolute_path", "Caminhos absolutos não são aceites; o destino é gerido pela aplicação."}}
	}
	if dangerousRe.MatchString(clean) {
		findings = append(findings, Finding{"warn", "dangerous_extension",
			"Executável/instalador: será descarregado mas NUNCA iniciado automaticamente."})
	}
	return clean, findings
}

// CheckRedirectPolicy decide se um redirecionamento Location é aceitável.
// Redirecionar para IP privado é o vetor SSRF clássico pós-302.
func CheckRedirectPolicy(from, to string, opts Options) []Finding {
	return CheckURL(to, opts)
}

// Limits impõe tetos absolutos independentemente da vontade do utilizador.
type Limits struct {
	MaxTaskSizeBytes   int64 // default 64 GiB
	MaxConcurrentTasks int   // default 16
	MaxOpenConnections int   // default 64
}

func DefaultLimits() Limits {
	return Limits{MaxTaskSizeBytes: 64 << 30, MaxConcurrentTasks: 16, MaxOpenConnections: 64}
}
