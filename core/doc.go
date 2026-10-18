// Package core é o núcleo partilhado do StreamVault: modelos de domínio,
// contratos de motores, licenciamento Ed25519, reconhecimento de links,
// análise de segurança, integridade e orquestração.
//
// Regras inegociáveis (ver docs/adr/):
//   - Não depende de qualquer interface gráfica.
//   - Não usa subprocessos binários externos no caminho de transferência.
//   - Downloads acontecem diretamente no dispositivo do utilizador.
package core
