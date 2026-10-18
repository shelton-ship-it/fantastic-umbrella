// Package license implementa VERIFICAÇÃO offline de licenças Ed25519.
//
// Este pacote contém APENAS a chave pública de verificação. A chave privada
// de emissão pertence ao serviço emissor (services/license-issuer) e NUNCA
// aparece aqui nem nos clientes compilados.
package license

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Formato canónico: a assinatura é calculada sobre SHA-256 da serialização
// JSON CANÓNICA (chaves ordenadas lexicograficamente, sem espaços) dos campos
// exceto "signature". Isto impede interpretações divergentes do mesmo documento.
const (
	FormatVersion  = 1
	SignatureField = "signature"
)

// Erros canónicos — a UI mapeia cada um para uma mensagem humana distinta.
var (
	ErrMalformed       = errors.New("license: documento malformado")
	ErrUnknownFormat   = errors.New("license: formato de licença desconhecido")
	ErrMissingField    = errors.New("license: campo obrigatório em falta")
	ErrBadSignature    = errors.New("license: assinatura criptográfica inválida")
	ErrUnknownKey      = errors.New("license: key_id não corresponde a nenhuma chave pública confiada")
	ErrProductMismatch = errors.New("license: licença emitida para outro produto")
	ErrNotYetValid     = errors.New("license: licença ainda não está válida (not_before futuro)")
	ErrExpired         = errors.New("license: licença expirada")
	ErrClockSkew       = errors.New("license: relógio local aparentemente incorreto; validação adiado")
)

// ActivationPolicy descreve regras de ativação associadas à licença.
type ActivationPolicy struct {
	MaxDevices       int  `json:"max_devices"`
	OfflineGraceDays int  `json:"offline_grace_days"` // 0 = puramente offline
	RevokeCheck      bool `json:"revoke_check"`       // exige contacto periódico com o emissor?
}

// Entitlements são os direitos comerciais concedidos. Campos novos podem ser
// adicionados pelo emissor sem partir clientes antigos (JSON ignora extras).
type Entitlements struct {
	AdFree          bool `json:"ad_free"`
	PriorityQueue   bool `json:"priority_queue"`
	AdvancedFilters bool `json:"advanced_filters"`
	TorrentEngine   bool `json:"torrent_engine"`
	LANTransfer     bool `json:"lan_transfer"`
}

// License é o documento assinado. Fields públicos serializados canonicamente.
type License struct {
	FormatVersion    int              `json:"format_version"`
	LicenseID        string           `json:"license_id"`
	ProductID        string           `json:"product_id"`
	Edition          string           `json:"edition"`
	IssuedAt         int64            `json:"issued_at"` // unix UTC s
	NotBefore        int64            `json:"not_before,omitempty"`
	ExpiresAt        int64            `json:"expires_at,omitempty"` // 0 = permanente
	Entitlements     Entitlements     `json:"entitlements"`
	ActivationPolicy ActivationPolicy `json:"activation_policy"`
	KeyID            string           `json:"key_id"`
	Signature        string           `json:"signature"` // hex ed25519
}

// CanonicalBytes devolve a representação canónica assinável. Implementação:
// map genérico -> re-marshalling com chaves ordenadas (encoding/json ordena
// maps por chave desde Go 1.x; garantimos recursivamente via json.RawMessage
// normalizado). Campos vazios omitempty já foram resolvidos na EMISSÃO — o
// emissor usa ESTA mesma função, pelo que cliente e servidor concordam.
func (l *License) CanonicalBytes() ([]byte, error) {
	// cópia sem signature
	type sansSig struct {
		FormatVersion    int              `json:"format_version"`
		LicenseID        string           `json:"license_id"`
		ProductID        string           `json:"product_id"`
		Edition          string           `json:"edition"`
		IssuedAt         int64            `json:"issued_at"`
		NotBefore        int64            `json:"not_before,omitempty"`
		ExpiresAt        int64            `json:"expires_at,omitempty"`
		Entitlements     Entitlements     `json:"entitlements"`
		ActivationPolicy ActivationPolicy `json:"activation_policy"`
		KeyID            string           `json:"key_id"`
	}
	s := sansSig{
		FormatVersion: l.FormatVersion, LicenseID: l.LicenseID, ProductID: l.ProductID,
		Edition: l.Edition, IssuedAt: l.IssuedAt, NotBefore: l.NotBefore,
		ExpiresAt: l.ExpiresAt, Entitlements: l.Entitlements,
		ActivationPolicy: l.ActivationPolicy, KeyID: l.KeyID,
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return b, nil
}

// SigningDigest é o hash sobre o qual a assinatura incide.
func (l *License) SigningDigest() ([32]byte, error) {
	b, err := l.CanonicalBytes()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// Keyring guarda as chaves públicas confiadas, indexadas por key_id.
// A rotação adiciona uma nova entrada SEM remover a antiga até que todas
// as licenças antigas tenham expirado ou sido substituídas por reemissão.
type Keyring struct {
	keys map[string]ed25519.PublicKey
}

func NewKeyring() *Keyring { return &Keyring{keys: map[string]ed25519.PublicKey{}} }

func (k *Keyring) Trust(keyID string, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("license: chave pública %s tem tamanho inválido", keyID)
	}
	k.keys[keyID] = pub
	return nil
}

// Status é o resultado discriminado da validação (cada caso exige mensagem
// diferente na UI — nunca um booleano opaco).
type Status int

const (
	StatusValid Status = iota
	StatusInvalidSignature
	StatusUnknownKey
	StatusWrongProduct
	StatusExpired
	StatusNotYetValid
	StatusMalformed
	StatusUnknownFormat
	StatusClockSkew
	StatusRevoked // decidido por política de revogação quando RevokeCheck ativo
)

func (s Status) String() string {
	names := [...]string{"valid", "invalid_signature", "unknown_key", "wrong_product",
		"expired", "not_yet_valid", "malformed", "unknown_format", "clock_skew", "revoked"}
	if int(s) < len(names) {
		return names[s]
	}
	return "malformed"
}

// ValidationResult transporta status + direitos + explicação auditável.
type ValidationResult struct {
	Status       Status
	Reason       string
	Entitlements Entitlements
	Permanent    bool
	ExpiresAt    time.Time
	KeyID        string
}

// Validator valida licenças contra um produto e um keyring.
type Validator struct {
	ProductID string
	Ring      *Keyring
	Now       func() time.Time // injetável p/ testes de relógio
}

// Validate executa TODAS as verificações determinísticas locais:
// formato → campos → assinatura → produto → datas. Não contacta servidores.
func (v *Validator) Validate(l *License) ValidationResult {
	fail := func(st Status, reason string) ValidationResult {
		return ValidationResult{Status: st, Reason: reason}
	}
	if l == nil {
		return fail(StatusMalformed, ErrMalformed.Error())
	}
	if l.FormatVersion != FormatVersion {
		return fail(StatusUnknownFormat, fmt.Sprintf("%s: esperado %d, obtido %d", ErrUnknownFormat, FormatVersion, l.FormatVersion))
	}
	for name, val := range map[string]string{
		"license_id": l.LicenseID, "product_id": l.ProductID,
		"edition": l.Edition, "key_id": l.KeyID, "signature": l.Signature,
	} {
		if val == "" {
			return fail(StatusMalformed, fmt.Sprintf("%v: %s", ErrMissingField, name))
		}
	}
	if l.IssuedAt == 0 {
		return fail(StatusMalformed, fmt.Sprintf("%v: issued_at", ErrMissingField))
	}
	sig, err := hex.DecodeString(l.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fail(StatusMalformed, "assinatura não é hex ed25519 válido")
	}
	pub, ok := v.Ring.keys[l.KeyID]
	if !ok {
		return fail(StatusUnknownKey, ErrUnknownKey.Error()+": "+l.KeyID)
	}
	digest, err := l.SigningDigest()
	if err != nil {
		return fail(StatusMalformed, err.Error())
	}
	if !ed25519.Verify(pub, digest[:], sig) {
		return fail(StatusInvalidSignature, ErrBadSignature.Error())
	}
	if l.ProductID != v.ProductID {
		return fail(StatusWrongProduct, fmt.Sprintf("%s: licença=%s app=%s", ErrProductMismatch, l.ProductID, v.ProductID))
	}
	now := v.now()
	// Proteção honesta contra relógio retrocedido: se "agora" for anterior à
	// data de emissão em mais de 24h, o dispositivo tem relógio incorreto.
	if now.Add(24 * time.Hour).Before(time.Unix(l.IssuedAt, 0)) {
		return fail(StatusClockSkew, ErrClockSkew.Error())
	}
	if l.NotBefore > 0 && now.Before(time.Unix(l.NotBefore, 0)) {
		return fail(StatusNotYetValid, ErrNotYetValid.Error())
	}
	res := ValidationResult{
		Status: StatusValid, Entitlements: l.Entitlements, Permanent: l.ExpiresAt == 0,
		KeyID: l.KeyID,
	}
	if l.ExpiresAt > 0 {
		res.ExpiresAt = time.Unix(l.ExpiresAt, 0)
		if now.After(res.ExpiresAt) {
			return fail(StatusExpired, ErrExpired.Error())
		}
	}
	return res
}

func (v *Validator) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now().UTC()
}

// Parse descodifica JSON de uma licença fornecida pelo utilizador.
func Parse(data []byte) (*License, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if _, ok := probe["format_version"]; !ok {
		return nil, fmt.Errorf("%w: format_version", ErrMissingField)
	}
	var l License
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields() // recusa campos desconhecidos => formato estrito versionado
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return &l, nil
}

func bytesReader(b []byte) *jsonReader { return &jsonReader{b: b} }

type jsonReader struct {
	b   []byte
	off int
}

func (r *jsonReader) Read(p []byte) (int, error) {
	if r.off >= len(r.b) {
		return 0, errEOF
	}
	n := copy(p, r.b[r.off:])
	r.off += n
	return n, nil
}

var errEOF = errors.New("EOF")

// Sign cria a assinatura canónica. Usada PELO EMISSOR (tests aqui simulam o
// emissor com uma chave temporária gerada no teste — nunca há chave privada
// hardcoded no pacote).
func (l *License) Sign(priv ed25519.PrivateKey) error {
	digest, err := l.SigningDigest()
	if err != nil {
		return err
	}
	l.Signature = hex.EncodeToString(ed25519.Sign(priv, digest[:]))
	return nil
}
