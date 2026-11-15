# 0037 — Buffers de socket do web com teto fixo

Status: aceita (conta e `rmem_max` de 7 MiB substituídos pela 0039 e pela 0038 em 2026-11-15; os tetos de socket ficam)
Data: 2026-11-15

## Contexto
A ADR 0036 fez o orçamento contar a memória que o web aloca, baixou o `GOMEMLIMIT` do web para 64 MiB e pôs teto
de 64 KiB nos buffers de socket **só do WebSocket**, mantendo o autoajuste do kernel (`tcp_rmem`/`tcp_wmem`) nas
demais conexões TCP e o buffer de ~7 MiB que o quic-go pede ao socket UDP. Rejeitou o teto em todas as conexões TCP
porque o caso medido na task 214 era o eco WebSocket travado.

Fato novo: a janela A da carga da task 215 (2026-11-15 00:35:47–00:39:56 UTC, `v0.2.1-54-g91c7f25`, mesmo cenário
da 214, `test/load/RESULTS.md` e `test/load/results/budget-215a/`):
- `anon` máximo 64 552 960 bytes (61,6 MiB), dentro da meta de 72 MiB: a parte do heap da ADR 0036 funcionou;
- `memory.current` colado em 96 MiB a janela inteira, `memory.events max` 0 → 304 563, `memory.peak`
  **104 792 064**, acima do próprio `MemoryMax` (100 663 296);
- memória de kernel (`memory.current − anon − file`) de **52–65 MiB** em todas as janelas de 30 s, com 220 conexões
  h1 enviando cabeçalhos de ~1 MiB (1,3 GB no total) e 14 conexões h3 (3,8 GB), e só 16 WebSocket (≤ 4 MiB);
- 1805 conexões h1 fechadas sem resposta, todas por prazo de escrita do cliente (10 s sem o servidor aceitar
  bytes), nenhuma por recusa nem por `FS_MAX_CONNS` (`max_active` 220 < 250).

Leitura:
1. O que passa do `memory.max` só pode ser carga forçada do kernel: no cgroup v2, o buffer de recepção de socket
   (`sock` no `memory.stat`) é cobrado do cgroup do processo e, na recepção, a cobrança que falha é forçada
   (passa do limite) e marca pressão de memória no socket. Heap e páginas de arquivo não passam do `memory.max`.
   O `memory.peak` acima do `MemoryMax` é a assinatura dos buffers de recepção.
2. Com o autoajuste, cada socket TCP pode crescer até `tcp_rmem[2]` (6 MiB no Debian 13) e o UDP do QUIC tem
   `SO_RCVBUF` de 7 MiB (o kernel dobra: 14 MiB). Com 1 vCPU saturada (web 52%, store 23%), o web lê mais devagar
   do que 234 clientes enviam; as filas enchem até o cgroup inteiro, e o kernel tira o resto do `anon` por reclaim
   (os 304 563 eventos `max`). Os ~55 MiB medidos dão ~230 KiB por socket h1: não há teto, só o limite do cgroup.
3. Com o cgroup sob pressão, o TCP para de abrir a janela e descarta segmentos (poda da fila de recepção): é a
   explicação provável das 1805 conexões em que o cliente não conseguiu escrever por 10 s. Não foi medido
   (faltam os contadores `TcpExt` e o `sock` do `memory.stat` nos brutos); a nova carga mede.
4. Baixar o orçamento para 16 MiB (o ajuste previsto pela ADR 0036 item 6) não muda isso: o `anon` já está na
   meta, e a memória de kernel ocupa o que sobrar do cgroup, qualquer que seja o orçamento.

Sysctls (`tcp_rmem`, `tcp_wmem`, `udp_mem`) valem para a máquina inteira: o NATS e o store trocam todo o tráfego
de pacotes por TCP em loopback, e a capture depende da vazão deles; teto global derrubaria a vazão do caminho de
captura para limitar um serviço. O `MemoryMax` e as RNF ficam como estão (ADR 0005, spec 000).

## Decisão
**Todo socket do web tem buffer de kernel com teto fixo, definido pelo próprio web, e a conta da ADR 0036 passa a
somar esses tetos.** Altera os itens 3 e 5 da ADR 0036; o resto da 0036 (orçamento de 24 MiB, reserva da memória
alocada, `bufio` de 16 KiB, janelas do quic-go, `GOMEMLIMIT` 64 MiB, meta do item 6) continua valendo.

1. **TCP: `SO_RCVBUF` e `SO_SNDBUF` de 16 KiB em toda conexão TCP aceita pelo web** (portas 80/443/8080/8443,
   h1, TLS, h2, h2c, WebSocket sobre HTTP/1.1 ou h2), aplicados logo depois do `accept` e antes da primeira leitura
   (antes do handshake TLS e da detecção). O kernel dobra o valor pedido: até **32 KiB** de recepção e **32 KiB**
   de envio por conexão, contando a ocupação real dos buffers (`truesize`). Com `FS_MAX_CONNS` = 250, até
   **15,6 MiB** com todas as conexões cheias nos dois sentidos.
   - O valor é fixado no socket aceito, não no listener: o SYN-ACK (janela, escala e opções) continua sendo o dos
     sysctls da ADR 0011; muda só a janela anunciada depois do handshake, que fica pequena (~16–24 KB).
   - Substitui os 64 KiB do WebSocket (ADR 0036 item 3): a sessão usa o mesmo teto das outras conexões, já
     aplicado no `accept`; o eco de 1 MiB continua funcionando, mais devagar.
   - Falha no `setsockopt` só registra aviso (como o TFO) e a conexão segue.
   - Efeito aceito: vazão por conexão limitada pela janela (~16–24 KB por RTT na recepção, ~32 KB no envio;
     ~1 MB/s a 20 ms de RTT). O espelho analisa como a conexão chega, não mede vazão (spec 000); `size=` até
     `FS_SIZE_MAX` continua funcionando, mais devagar.
2. **UDP do QUIC: `SO_RCVBUF` e `SO_SNDBUF` de no máximo 1 MiB** (o kernel dobra: até **2 MiB** por sentido). O
   wrapper `udpConn` (`internal/web/h3udp.go`) limita o valor que o quic-go pede a 1 MiB, nos dois sentidos; como o
   wrapper não expõe `SyscallConn`, o quic-go não tenta `SO_RCVBUFFORCE` nem avisa. O sysctl
   `net.core.rmem_max`/`wmem_max` de 7 MiB (ADR 0019) continua, pois 1 MiB passa do padrão do kernel (208 KiB).
   Datagramas descartados com a fila cheia são retransmitidos pelo QUIC; a captura os vê antes do socket.
3. **Sem sysctl novo e sem mudança na unit**: `tcp_rmem`, `tcp_wmem`, `udp_mem` e o `MemoryMax=96M` do web ficam
   como estão; raw, dns, store, NATS e capture não mudam.
4. **Conta (cgroup do web, `MemoryMax=96M`)**, substitui a tabela do item 5 da ADR 0036:

| Parte | Teto | De onde vem |
| --- | --- | --- |
| Go (heap, pilhas, runtime) | 64 MiB (`GOMEMLIMIT`) | como na ADR 0036 (medido: 61,6 MiB de pico, ~48 MiB estável na janela A) |
| Buffers TCP | 15,6 MiB | 250 × (32 KiB de recepção + 32 KiB de envio), item 1 |
| Buffers UDP do QUIC | 4 MiB | 2 MiB de recepção + 2 MiB de envio, item 2 |
| Slab e o resto do kernel | ~4 MiB | medido (janela B da 215: kernel 4–12 MiB com 12 WebSocket a 256 KiB) |
| Páginas de arquivo | ~4–8 MiB, recuperáveis | binário e htdocs (medido) |
| **Total** | **≤ 96 MiB no pior caso; meta medida ≤ 88 MiB** | |

   No cenário da janela A, o esperado é kernel ≤ ~13 MiB (220 × 32 KiB de recepção + 2 MiB do UDP + slab) e
   `memory.current` ≤ ~78 MiB.
5. **Meta medida (tester)**: a do item 6 da ADR 0036, sem mudança (`memory.peak` ≤ 92 274 688, `memory.events max`
   delta 0, `anon` ≤ 75 497 472, sem reinício, orçamento ≤ 25 165 824 e recusas crescendo), mais a memória de
   kernel por janela de 30 s com o `sock` do `memory.stat` e os contadores `TcpExtTCPRcvQDrop`,
   `TcpExtTCPMemoryPressures`, `TcpExtPruneCalled`, `TcpExtRcvPruned`, `TcpExtTCPOFODrop` e `UdpRcvbufErrors`
   (`nstat`) antes e depois. As conexões h1 fechadas sem resposta não têm meta: o tester registra quantas e por
   qual causa, comparando com as 1805 da 215.
   Se a meta não for atingida com o kernel dentro da conta, o próximo ajuste é o orçamento de 16 MiB (ADR 0036
   item 6); se o kernel passar da conta, volta ao architect.

## Alternativas consideradas
- **Sysctls menores (`tcp_rmem`/`tcp_wmem`/`udp_mem`)**: limitam também o loopback do NATS e do store, que levam
  todos os pacotes da captura; `udp_mem` é global e em páginas, sem efeito por cgroup.
- **Teto só durante a leitura do cabeçalho h1** (e voltar ao autoajuste depois): o Linux não volta ao autoajuste
  depois de um `SO_RCVBUF` explícito; a conexão ficaria com um segundo valor fixo, maior, sem teto útil na conta, e
  o h2, o TLS e o h3 continuariam sem teto.
- **Teto no listener** (herdado pelo `accept`): muda o SYN-ACK do espelho (janela e escala), que é a resposta
  TCP documentada da ADR 0011.
- **Valores maiores (64 KiB, como o WebSocket)**: 250 × 256 KiB = 62,5 MiB, não cabe com o `GOMEMLIMIT` de 64 MiB.
- **Contar os buffers de kernel no orçamento de entrada**: o web não sabe quanto o kernel guardou em cada socket
  sem `SIOCINQ` por leitura, e o orçamento esgotado passaria a valer contra memória que o web não controla; o teto
  fixo por socket é verificável por `getsockopt` e somável na conta.
- **Baixar o `GOMEMLIMIT` ou o orçamento** de novo: o `anon` já está na meta; o kernel ocuparia o espaço liberado.
- **Subir o `MemoryMax`**: exige o humano (ADR 0005, specs/002 item 5) e não põe teto no kernel.

## Consequências
- Spec 005 RF-12 (buffers de socket por conexão, UDP do QUIC), spec 012 RF-07 (16 KiB no lugar de 64 KiB), spec
  011 (buffer UDP), spec 016 RF-02 (o `rmem_max` de 7 MiB é teto, o web pede 1 MiB) e spec 001 (ameaças)
  atualizadas.
- Tarefa 215: implementer-web aplica os itens 1–2 com testes por `getsockopt` (Linux); tester repete a janela A
  com as medidas do item 5. Nenhum contrato muda (transport parameters, SETTINGS, eventos); a janela TCP anunciada
  pelo espelho depois do handshake fica menor, visível no pcap.
