# 0036 — Conta de memória do web medida sob ataque

Status: aceita
Data: 2026-11-14

## Contexto
A ADR 0033 fixou o orçamento global de entrada do web (`FS_WEB_INPUT_BUDGET`, padrão 40 MiB, 8–64 MiB) com a conta
"40 MiB de orçamento + 8 MiB do tracker QUIC, ~32 MiB do `GOMEMLIMIT` para o resto". A carga da task 214
(2026-11-14, `v0.2.1-42-gb76caec`, `test/load/RESULTS.md` e `test/load/results/budget-214/`) é o fato novo: com
220 conexões h1 segurando cabeçalhos de ~1 MiB, 16 WebSocket com o eco travado e 14 conexões h3 com HEADERS
incompletos, o orçamento chegou a 41 943 037 bytes e recusou 2540 reservas, o processo não reiniciou, mas:
- `memory.current` ficou em 96,0 MiB nos primeiros 150 s, `memory.events max` 0 → 47 403, `memory.peak`
  104 382 464 bytes;
- a memória do cgroup que não é `anon` nem `file` (memória de kernel: buffers de socket, slab) chegou a
  **68 MiB** aos 10 s, com `anon` em 28 MiB, e caiu para ~4 MiB depois dos 120 s;
- o `anon` subiu de 30 MiB (250 conexões, orçamento vazio) para **88,6 MiB** com o orçamento cheio: ~1,4 byte de
  `anon` por byte reservado, acima do `GOMEMLIMIT` de 80 MiB.

A leitura do código (`internal/web`, `pkg/h1`, `pkg/quicparse`) explica os três números:
1. **O orçamento conta menos do que o web retém.** O h1 reserva os bytes de cada linha uma vez, mas guarda duas
   cópias: `RawHead` (que cresce por `append`, com capacidade até ~1,25× o tamanho) e as strings de `Fields`
   (`string(content)` em `parseField`); um cabeçalho de 1 MiB custa ~2,25 MiB de heap. O WebSocket reserva 1 MiB,
   mas o `wc.Read` do `coder/websocket` junta a mensagem num buffer que cresce até ~2 MiB, e a mensagem fica
   retida enquanto o eco espera a janela. O `r.buf` do HEADERS h3 também cresce por `append`.
2. **Retenção por conexão fora do orçamento.** Cada conexão h1 aloca um `bufio.Reader` de 64 KiB (220 × 64 KiB =
   14 MiB só disso, metade do `anon` de base medido), e o `tap` acumula até 64 KiB por sentido antes de publicar um
   pedaço de `stream.bytes` (até 250 × 2 × 64 KiB = 32 MiB no pior caso).
3. **Memória de kernel fora da conta.** Uma sessão WebSocket com o eco travado para de ler: o buffer de recepção
   (`tcp_rmem` até 6 MiB) e o de envio (`tcp_wmem` até 4 MiB) enchem e são cobrados do cgroup do web; 16 sessões
   explicam os 68 MiB do início. O quic-go, sem configuração, deixa a janela de recepção crescer até 6 MiB por
   stream e 15 MiB por conexão.

Subir o `MemoryMax` não é a saída (ADR 0005, spec 016 RF-07; mudaria só o número do pior caso). O `GOMEMLIMIT` do
web não é fixado por ADR (só a spec 016 o cita indiretamente pela unit) e pode mudar.

## Decisão
**O orçamento passa a contar a memória que o web de fato retém, a retenção por conexão diminui e a memória de
kernel ganha teto e lugar próprio na conta.** Substitui os itens 1 (padrão e faixa), 2 (reserva do WebSocket) e 3
(conta) da ADR 0033; o resto da 0033 continua valendo.

1. **Padrão e faixa.** `FS_WEB_INPUT_BUDGET` padrão **24 MiB** (25 165 824), aceita **8 MiB–32 MiB**
   (8 388 608–33 554 432); fora disso o web não sobe (como antes).
2. **Reservar o que é alocado, não o que chegou.** Todo caminho do orçamento reserva a capacidade que aloca para
   guardar bytes do cliente, incluindo cópias:
   - **h1**: o cabeçalho (e os trailers) reserva o crescimento da capacidade de `RawHead`, os bytes de cada campo
     copiado para `Fields` e o crescimento da fatia `Fields` (~2,3× os bytes lidos hoje; o implementador pode
     reduzir a cópia, por exemplo com campos como substrings de uma única string, desde que a reserva siga a
     alocação). O teto de 1 MiB por cabeçalho continua sendo dos bytes do cabeçalho, não da reserva.
   - **h3**: o HEADERS em espera reserva o crescimento da capacidade de `r.buf` (ou aloca `r.buf` com capacidade
     exata ao reservar). O teto de 2 MiB por conexão é da reserva.
   - **WebSocket**: cada sessão reserva **2 MiB** (2 × `wsReadLimit`) no Upgrade, em vez de 1 MiB. O teto de 32
     sessões continua; com o padrão de 24 MiB, no máximo 12 sessões cabem no orçamento vazio, e as demais recebem
     503 antes do 101.
   - **h2**: sem mudança (o custo por campo da 0033 já inclui a estrutura).
   - **`tap` (`stream.bytes`)**: o acúmulo pendente de cada sentido (até 64 KiB, `event.StreamChunkBytes`) reserva
     do orçamento. Sem orçamento, o `tap` não recusa nada: publica na hora o que tem (pedaço menor que 64 KiB,
     permitido pelo contrato "até 64 KiB") e segue sem reter. Não conta como recusa em
     `web_input_budget_denied_total`.
   Cada caminho tem um teste que compara a reserva com a memória retida medida (`runtime.ReadMemStats` depois de
   `runtime.GC()`, com um cabeçalho h1 de 999 424 bytes, um HEADERS h3 de ~1 MiB e uma mensagem WebSocket de
   1 MiB − 64): a reserva fica ≥ 90% do `HeapAlloc` retido e o contador volta a zero no fim.
3. **Retenção por conexão menor (fora do orçamento, limitada por `FS_MAX_CONNS`).**
   - `bufio.Reader` do HTTP/1 de 64 KiB para **16 KiB** (`readBufSize`).
   - Conexão HTTP/1 que vira WebSocket (TLS ou claro) tem `SO_RCVBUF` e `SO_SNDBUF` de **64 KiB** no socket TCP,
     aplicados depois de aceitar o Upgrade e antes do 101 (o kernel dobra: ≤ 256 KiB por sessão nos dois
     sentidos; 32 sessões ≤ 8 MiB). O WebSocket sobre h2 fica no controle de fluxo do h2, sem mudança. As demais
     conexões TCP do web mantêm o autoajuste do kernel.
   - quic-go: `MaxStreamReceiveWindow` **2 MiB** e `MaxConnectionReceiveWindow` **4 MiB** (padrões do quic-go:
     6 MiB e 15 MiB). As janelas iniciais ficam nos padrões, então os transport parameters anunciados não mudam.
4. **`GOMEMLIMIT` do web de 80 MiB para 64 MiB** (`deploy/systemd/finger-sniffer-web.service` e o teste da unit).
   Raw, dns e capture ficam em 80 MiB.
5. **Conta (cgroup do web, `MemoryMax=96M`).**

| Parte | Teto | De onde vem |
| --- | --- | --- |
| Go (heap, pilhas, runtime) | 64 MiB (`GOMEMLIMIT`) | base com 250 conexões ~20 MiB (30 MiB medidos com `bufio` de 64 KiB, menos ~10 MiB do item 3), tracker QUIC ≤ 8 MiB, orçamento ≤ 24 MiB de retenção real, e ~12 MiB de folga para o lixo do GC (eventos, codificação para o NATS) |
| Kernel (buffers de socket, slab, pilhas) | ~24 MiB | WebSocket ≤ 8 MiB (item 3), socket UDP do QUIC ≤ 14 MiB (7 MiB dobrados, ADR 0019; na carga ficou perto de zero), slab e o resto ~4 MiB (medido) |
| Páginas de arquivo | ~4–8 MiB, recuperáveis | binário e htdocs (medido) |
| **Total** | **≤ 96 MiB no pior caso; meta medida ≤ 88 MiB** | |

6. **Meta medida (tester).** No mesmo cenário da task 214 (`test/load/budget.sh -duration 4m`, padrão
   `-h1 220 -ws 16 -h3 14`), com o web reiniciado antes da janela (para o `memory.peak` começar nela):
   - `memory.peak` do web **≤ 88 MiB** (92 274 688 bytes: margem de 8 MiB abaixo de 96M);
   - `memory.events max` sem nenhum evento na janela (delta 0);
   - `anon` máximo **≤ 72 MiB** (75 497 472 bytes);
   - `NRestarts` 0, `oom_kill` 0, mesmo `MainPID`;
   - `web_input_budget_used_bytes` ≤ 25 165 824 e `web_input_budget_denied_total` crescendo.
   E um cenário que exercite o 503 do WebSocket por orçamento (item 2), com o total de conexões abaixo de
   `FS_MAX_CONNS` e as novas abaixo de `FS_MAX_NEW_CONNS_PER_S`, com as mesmas metas de memória.
   Se a meta não for atingida, o primeiro ajuste é baixar o padrão dentro da faixa (16 MiB), por tarefa do
   architect, sem nova ADR; subir o `MemoryMax` continua exigindo o humano (specs/002, item 5).

## Alternativas consideradas
- **Subir o `MemoryMax` do web**: muda a ADR 0005 e o orçamento da VPS de 967 MiB; não corrige a conta errada
  (o orçamento continuaria contando menos da metade do que retém).
- **Só baixar o padrão** (por exemplo 16 MiB) sem contar as cópias: chega à meta neste cenário por acaso; outro
  perfil (cabeçalhos h1 com linhas longas, que crescem por `append` várias vezes) volta a passar.
- **Contar no orçamento os buffers fixos por conexão** (`bufio`, TLS): o orçamento esgotado passaria a recusar
  conexões novas em vez de entrada retida, papel do `FS_MAX_CONNS`; eles ficam na base, limitados por ele, e
  menores.
- **`SO_RCVBUF`/`SO_SNDBUF` pequenos em todas as conexões TCP do web** (ou `tcp_rmem`/`tcp_wmem` menores por
  sysctl): limitaria também respostas grandes (`/r?size=` até `FS_SIZE_MAX`) e, no sysctl, o store; o caso medido é
  o do WebSocket com eco travado, que fica limitado sem afetar o resto.
- **Mudar o tamanho do pedaço de `stream.bytes`**: é contrato (ADR 0018); publicar antes da hora quando falta
  orçamento já cabe no "até 64 KiB".

## Consequências
- Spec 005 RF-12 (padrão, faixa, `tap`, buffers por conexão), spec 012 RF-07 (2 MiB por sessão, buffers do
  socket), spec 011 (janelas do quic-go), spec 016 RF-07 (`GOMEMLIMIT` do web) e spec 001 (ameaças) atualizadas.
- `.env.example`: `FS_WEB_INPUT_BUDGET=25165824` e o comentário com a faixa nova. O `env-merge` não sobrescreve o
  valor já presente na vps602 (41 943 040, fora da faixa nova): o web não subiria. Quem implanta troca o valor no
  `/finger-sniffer/etc/finger-sniffer.env` antes do `make deploy`.
- Tarefa 215: implementer-web aplica os itens 1–4 com os testes do item 2; tester repete a carga e registra o item 6.
- O teste de contrato e os goldens não mudam: transport parameters, SETTINGS h2 e campos dos eventos ficam iguais;
  muda só o tamanho de alguns pedaços de `stream.bytes` sob orçamento esgotado.
