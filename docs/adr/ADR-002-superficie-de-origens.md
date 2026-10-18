# ADR-002 — Superfície de origens: "quase tudo" ≠ extrator universal

## Contexto
O produto deve descarregar, diretamente no dispositivo do utilizador:
ficheiros HTTP/HTTPS diretos (imagens, música, vídeo), torrents/magnets e
conteúdo de plataformas de vídeo. O briefing proíbe explicitamente um
"extrator universal fictício" e o contornamento de DRM, autenticação e
controlos de acesso de terceiros.

## Decisão
A cobertura é definida por CAMADAS, com honestidade sobre limites:

1. **Camada 1 — HTTP/HTTPS direto (Motor 2):** qualquer URL que o próprio
   sistema permita aceder sem autenticação quebrada (imagens, áudio, vídeo
   em URLs retas, atualizações, repositórios). Retoma via Range quando
   suportada. Cobertura máxima e totalmente legítima.

2. **Camada 2 — BitTorrent (Motor 3):** magnet links e ficheiros .torrent
   através da interface Engine (candidato: anacrolix/torrent, MIT — ver
   ADR-001). Cobre distribuição P2P de imagens ISO, música, vídeo, etc.

3. **Camada 3 — Adaptadores de origem (Módulo 5):** ligações a plataformas
   (YouTube, Vimeo, redes sociais, stores) NÃO são suportadas por extração
   embutida. Cada plataforma exigiria um adaptador específico, mantido,
   testado e aprovado pelo utilizador (Módulo 12), respeitando ToS,
   autenticação do próprio utilizador e ausência de DRM. Um adaptador só
   declara capacidades reais; se uma origem não é suportada, a aplicação
   explica a limitação e devolve o erro tipado correspondente.

4. **Fora de scope permanente:** streams HLS/DRM protegidos, conteúdo atrás
   de login alheio, contornamento de restrições técnicas (princípios 11 e
   26 do briefing). O pipeline legado (HLS/.bin/ChaCha20) foi excluído
   exatamente por operar nesta zona.

## Consequências
- aria2c cobre muitos protocolos (FTP/SFTP Metalink), mas isso não altera
  a decisão da ADR-001: protocolos extra podem ser adicionados como
  adaptadores Go nativos (golang.org/x/crypto/ssh para SFTP, stdlib p/ FTP
  via biblioteca auditada) SEM reintroduzir GPL ou subprocessos.
- A promessa comercial correta é: "downloads diretos + torrent no teu
  dispositivo; extensível por adaptadores aprovados", nunca "baixa tudo de
  qualquer site".
- O Módulo 5 (Link Recognition) decide deterministicamente a camada; o
  Módulo 6 (Security Analyzer) valida antes de qualquer transferência.

## Estado
Aceite. Vincula as Fases 1 (contratos DownloadSource/adaptadores), 2, 3, 5
e 11.
