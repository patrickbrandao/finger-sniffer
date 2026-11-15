# 000 — Visão geral

Status: aprovada
Depende de: —

## Contexto
Clientes, proxies e túneis podem alterar o tráfego sem que o cliente perceba: cabeçalhos reescritos, ClientHello
TLS refeito, conexões reaproveitadas ou fechadas por terceiros, pilha TCP diferente, resolvedor DNS trocado.
O finger-sniffer é um **servidor espelho**: recebe conexões em portas capturadas, registra byte a byte e pacote a
pacote como elas chegaram e expõe tudo, cru e analisado, por uma API fora da captura. Serve a
clientes que repetem a sondagem por caminhos diferentes (direto, proxies, túneis) e comparam o que o espelho viu.

Documento de origem dos requisitos: "Servidor espelho de análise de conexões" (incorporado nas specs 003–017; o
arquivo original não é versionado). O projeto é independente de consumidores específicos (ADR 0028).

## Usuários
- **Scripts de teste** de clientes, proxies e túneis: fazem sondagens marcadas com probe ID, repetidas por caminhos
  diferentes, e consultam a API para comparar o que o espelho viu.
- **Qualquer software** que queira analisar detalhes profundos de uma conexão: a API é genérica.
- **Visitante humano**: abre a página estática em `https://finger-01.badblock.net.br/` (pelo traefik do servidor)
  ou em `https://<nome>:8443/` e assiste, ao vivo, ao feed global do tráfego que chega ao servidor, servido pela
  porta não capturada.
- Não há administradores nem contas (servidor de testes).

## Objetivos e medida de sucesso
O MVP está pronto quando:
1. os 13 casos da matriz de testes (spec 017) rodam de ponta a ponta contra o `finger-01` pelo caminho direto e cada
   registro traz os campos das specs 008–013; a comparação por outros caminhos (proxies, túneis) é do cliente, a
   quem o espelho entrega receitas genéricas e campos estáveis (ADRs 0022 e 0028);
2. JA3, JA4, JA4T e Akamai HTTP/2 de curl, Go, Chrome e Firefox batem com FoxIO `ja4` e `tshark` aplicados ao
   mesmo pcap;
3. as metas de RNF abaixo são atingidas no teste de carga, medidas como na ADR 0022 (feed p99, API e registro p95).

## Escopo
- Servidor web nas portas capturadas TCP 8080/8443 e UDP 8443 (80/443 são do traefik do host, ADR 0038):
  HTTP/1.0, HTTP/1.1, h2 (ALPN), h2c (prior knowledge e Upgrade), HTTP/3/QUIC, WebSocket (`ws://`,
  `wss://`), TLS em qualquer porta; detecção de protocolo pelos primeiros bytes.
- Respostas controláveis pela URL (status, enquadramento, keep-alive, fechamento, RST, atrasos, 1xx, WebSocket).
- Arquivos estáticos de `/finger-sniffer/htdocs` com MIME correto (página informativa em inglês).
- Portas TCP cruas 7, 21, 22, 25, 110, 143, 587, 993 (echo, banner, sink, source; TLS opcional).
- DNS autoritativo da zona `finger-west-01.badblock.net.br` (UDP/TCP 53), registrando resolvedores, EDNS e ECS.
- Captura de pacotes na `ens192` com offloads desligados, pacotes na íntegra (inclusive o tráfego do traefik e dos
  sites do host), retenção curta.
- Análise IP, TCP, TLS, HTTP/1, HTTP/2, HTTP/3, WebSocket e DNS, com fingerprints (JA3, JA3N, JA4, JA4_r, JA4_o,
  JA4 stable, JA4T, JA4H, Akamai h2, p0f).
- API JSON `/api/v1` em 9000 (HTTPS) e 9001 (HTTP), sem captura, com consultas, pcap, bytes crus, SSE e WebSocket.
- Endpoints de status, saúde e métricas Prometheus.
- Execução por systemd; deploy automático por rsync a partir da máquina local.

## Fora de escopo
- Comparar caminhos (direto × proxy): é responsabilidade do cliente.
- Histórico longo, relatórios, banco permanente.
- Multi-servidor, alta disponibilidade, réplica.
- Contas de usuário, login, autorização.
- Modo reverse-proxy (encaminhar para backend) e atalho de probe do Kubernetes do fingerproxy.
- O fingerproxy como dependência: é só referência de técnicas.

## MVP
Todo o escopo acima, inclusive HTTP/3 e DNS. Entregue nas fases do PLAN.md; a versão `v0.1.0` marca o MVP.

## Restrições
- Máquina única: `finger-01.tmsoft.com.br` (também `finger-01.badblock.net.br`; VM VMware, Debian 13, kernel 6.12,
  16 vCPU, 32 GB RAM, NVMe de 111 GB, NIC `ens192` vmxnet3), IPv4 170.247.40.86, IPv6 2804:231c:e500:cafe::86.
  Acesso `ssh -p 48022 root@finger-01.tmsoft.com.br` (ADR 0038).
- No mesmo IP já existem sshd (48022) e snmpd (48161), que ficam fora da captura, e o traefik em container (TCP
  80/443/8081, UDP 443) com sites, cujo tráfego é capturado. O espelho usa no máximo metade das vCPU e 6 GiB de RAM
  (fatia `finger-sniffer.slice`, ADR 0039) e não mexe no resto do host.
- Projeto em `/finger-sniffer` no servidor; fontes editados localmente e enviados por rsync.
- Servidor de testes e desenvolvimento: qualquer ação nele pode ser feita sem aprovação, da forma mais automática.
- Equipe: 1 humano + agentes, sem prazo rígido.
- Identificadores, endpoints, chaves JSON em inglês; comentários de código em pt-BR; página web em inglês.
- Licença Apache-2.0; JA4+ sob FoxIO License isolado (ADR 0010).
- Privacidade: API totalmente aberta; tráfego de terceiros visível por até 10 min (ADR 0007).

## Requisitos
- RNF-01: 400 conexões simultâneas e 100 conexões novas/s com análise completa (ADR 0039; provisório até a carga
  oficial no finger-01). Acima do limite do modo degradado (configurável, padrão acima desta garantia para absorver
  o tráfego alheio; spec 004 RF-11, ADRs 0030 e 0039) degrada:
  mantém o resumo, corta o pcap e marca `degraded` no registro.
- RNF-02: evento ao vivo entregue ao cliente da 9000 em < 1 s após o espelho ter o fato (o pacote chegar ou o
  evento de aplicação ser publicado; `ts` do evento, ADR 0025).
- RNF-03: `GET` de conexão ou probe com p95 < 100 ms.
- RNF-04: registro completo disponível em ≤ 500 ms após o fim da conexão (p95), TCP e QUIC; no QUIC, o fim é o
  CONNECTION_CLOSE visto pelo web (ADR 0026).
- RNF-05: retenção padrão de 10 min (`FS_RETENTION`) e teto de 8 GiB (`FS_STORE_MAX_BYTES`, ADR 0039); o primeiro limite
  atingido expurga o mais antigo.
- RNF-06: tempos em UTC com nanossegundos; relógio sincronizado por NTP.
- RNF-07: nenhum frame capturado maior que MTU + 14 bytes (prova de que não há agregação por offload).
- RNF-08: página web em inglês, HTML semântico, sem cookies, sem recursos de terceiros.

## Critérios de aceite
- [ ] Os três itens de "Objetivos e medida de sucesso" verificados e registrados no PR da `v0.1.0`.

## Decisões relacionadas
- specs/decisions/0001-decisoes-iniciais.md
- specs/decisions/0007-api-aberta-e-feed-global.md
- specs/decisions/0012-retencao-curta.md
- specs/decisions/0022-prova-do-mvp-no-espelho.md
- specs/decisions/0026-fechamento-rapido-e-ajustes-da-release.md
- specs/decisions/0038-servidor-finger-01-e-coexistencia-com-o-traefik.md
- specs/decisions/0039-limites-e-metas-no-finger-01.md
