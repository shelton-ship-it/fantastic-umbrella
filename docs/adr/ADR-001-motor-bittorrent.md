# ADR-001 — Seleção do motor BitTorrent (aria2c vs anacrolix/torrent)

- **Estado:** Aceite (proposta registada na Fase 0; decisão final confirmada antes da Fase 3)
- **Data:** 2026-10-19
- **Contexto:** O pipeline legado (`process.yml`, "StreamVault Process (Leve)") utilizava libtorrent e foi alterado para `aria2c`. O briefing do novo produto lista `github.com/anacrolix/torrent` como candidato, sujeito a auditoria. Esta ADR compara as duas opções face aos requisitos obrigatórios.

## Opções avaliadas

### aria2c (aria2, GPL-2.0)
**Prós (reconhecidos — o utilizador tem razão quanto à amplitude):**
- Suporta HTTP(S), FTP, SFTP, BitTorrent e Metalink num único binário.
- Downsampling de segmentos, retoma robusta, RPC JSON/XML-RPC maduro.
- Anos de produção; lida bem com servidores hostis.

**Contras face aos requisitos deste produto:**
1. **Licença GPL-2.0.** Incompatível com distribuição comercial fechada dos clientes Windows/Android sem abrir o código-fonte completo das apps sob GPL. O produto pretende vender licenças (§5); a opção Go MIT elimina este conflito.
2. **Processo externo.** Exige empacotar/descarregar um binário C++ por plataforma e orquestrá-lo via RPC. Cria: superfície de atualização separada, verificação de integridade do próprio binário, conflitos de porta RPC, alertas de antivírus/SmartScreen contra binários não assinados, e impossibilidade de chamadas diretas a partir de código partilhado.
3. **Android.** aria2c nativo em Android exige NDK + porting mantido pela comunidade; sem suporte oficial. Integrar *dois* motores (Go no Windows, algo em Kotlin no Android) violaria o princípio "não manter duas implementações independentes da lógica de downloads".
4. **Sem hooks de domínio.** Progresso por ficheiro, políticas de segurança pré-transferência (Módulo 6), deteção de duplicados (M9) e eventos tipados (M13) teriam de ser reconstruídos por cima de um RPC genérico, com perda de contexto interno.
5. **Escopo desnecessário.** FTP/SFTP/Metalink não constam dos requisitos; o núcleo precisa apenas de HTTP(S) + BT/magnet.

### anacrolix/torrent (Go, MIT)
**Prós:** biblioteca in-process, mesma linguagem do core, licença compatível com uso comercial fechado, API rica (peers, metadados, seletor de ficheiros, verificação por piece-hash do protocolo), cross-compile trivial p/ Windows, caminho potencial p/ gomobile no Android.
**Contras/Riscos:** manutenção dependente de projeto quase individual; exige auditoria de dependências e versão mínima de Go; maturidade no Android desconhecida → gate de PoC documentado (Fase 7).

## Decisão
Adotar **anacrolix/torrent atrás da interface `engine.Engine`** (Módulo 1/Fase 1), mantendo o motor substituível sem reescrever fila/licenciamento/UI, conforme exige o briefing §3.1.

A largura de protocolos do aria2c é verdadeira mas **irrelevante para os requisitos**: o produto só necessita de HTTP(S) + BitTorrent, ambos cobertos pelo core Go. Nenhum componente do pipeline legado (HLS, `.bin`, ChaCha20, sharding, aria2c) é reutilizado.

## Consequências
- Zero dependências externas binárias nos instaladores.
- GPL evitado em toda a cadeia de distribuição.
- Risco de manutenção do anacrolix mitigado pela interface `Engine`: se a auditoria da Fase 3 reprovar o anacrolix, candidatos alternativos (ex.: implementação própria mínima p/ magnet+metadados, ou bindings libtorch licenciados zlib) podem ser trocados sem tocar nos Módulos 4, 5, 8, 9.
- Se surgir um requisito futuro real de FTP/Metalink, reabrir esta ADR.
