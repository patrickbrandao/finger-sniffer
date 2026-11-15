# 0033 — Orçamento de memória de entrada do web

Status: aceita (padrão, faixa, reserva do WebSocket e conta de memória: ver 0036; padrão 192 MiB, faixa 8–256 MiB
e conta para 768M: ver 0039, 2026-11-15)
Data: 2026-11-14

## Contexto
O web roda com `MemoryMax=96M` e `GOMEMLIMIT=80MiB` (spec 016) e aceita até `FS_MAX_CONNS` (250) conexões. A
auditoria de 2026-11-10 achou quatro caminhos em que um cliente anônimo, sozinho, faz o processo passar do limite
e ser morto pelo cgroup (todas as conexões em andamento caem e o ataque se repete a cada reinício):
- **155**: cabeçalho HTTP/1 de até 1 MiB por conexão × 250 conexões = 250 MiB retidos enquanto o cabeçalho não
  termina;
- **135**: o parser passivo do h2 guarda os campos HPACK de todos os streams da conexão até o fim dela;
- **134**: o web acumula o HEADERS de cada stream h3 até o frame completar, sem teto agregado;
- **136**: até 250 sessões WebSocket ecoando mensagens de 1 MiB (`wsReadLimit`) com a janela do cliente zerada.

Além desses, o tracker de Initials QUIC já tem teto próprio (4096 entradas, 8 MiB; task 143) e o HTTP/1 ganha
tetos por requisição que valem em qualquer desenho (1024 campos, task 131; extensões de chunk, task 133).

A pergunta (task 205) é se a resposta é um orçamento global de memória de entrada, compartilhado pelo serviço,
ou tetos pontuais por protocolo. As sugestões dos relatórios somadas (h1 32 MiB, h3 16 MiB, WebSocket 32 × 1 MiB,
h2 1 MiB × 250) passam de 300 MiB no pior caso: tetos independentes por protocolo só cabem nos 96M se cada um for
pequeno demais para o uso legítimo do próprio protocolo.

## Decisão
**Um orçamento global de entrada no web, mais tetos fixos por conexão.**

1. **Orçamento global** `FS_WEB_INPUT_BUDGET` (bytes; padrão **40 MiB** = 41943040; aceita 8 MiB–64 MiB; fora
   disso o web não sobe). Um contador único do processo: todo caminho que **retém bytes recebidos do cliente
   enquanto espera o resto** reserva antes de reter e devolve ao soltar (fim do cabeçalho, fim do stream, fim da
   sessão, conexão fechada, inclusive por pânico recuperado ou erro). A reserva nunca bloqueia: ou cabe, ou o
   caminho dá a resposta de estouro abaixo. Gauge `web_input_budget_used_bytes` e contador
   `web_input_budget_denied_total` no heartbeat.
2. **Tetos fixos por conexão ou requisição** (constantes no código, documentados nas specs de protocolo):

| Caminho | Teto por conexão/requisição | O que reserva do orçamento | Ao estourar (teto ou orçamento) |
| --- | --- | --- | --- |
| HTTP/1 cabeçalho (spec 009 RF-10) | 1 MiB e 1024 campos; trailers até 1024 campos | os bytes do cabeçalho lidos até o fim dele | 431 e registro `head_too_large`; trailers acima do teto → 400 |
| HTTP/1 extensões de chunk (spec 009 RF-03) | 256 KiB somadas por requisição | — (teto local) | para de listar pedaços, `chunks_truncated`; tamanho e SHA-256 seguem do corpo inteiro |
| h2 campos retidos pelo parser passivo (spec 010) | 1 MiB por conexão (custo por campo = 80 + nome + valor) | o mesmo custo | o parser continua decodificando (tabela dinâmica em sincronia), não guarda os campos e marca o stream `fields_truncated` |
| h2 streams simultâneos (spec 010) | `MAX_CONCURRENT_STREAMS` = 100 anunciado | — | o `x/net/http2` recusa o stream (RST_STREAM REFUSED_STREAM) |
| h3 HEADERS em espera (spec 011) | 2 MiB por conexão; 10 s para o HEADERS completar | os bytes do HEADERS acumulados | stream recusado com `H3_EXCESSIVE_LOAD` (0x0107); o prazo vencido também |
| WebSocket (spec 012) | 32 sessões simultâneas (h1 + h2); mensagem até 1 MiB; prazo de escrita do eco 30 s | 1 MiB por sessão, reservado no Upgrade | 503 antes do 101 (resposta normal, registrada); eco que não consegue escrever em 30 s encerra a sessão e o TCP (exceção da spec 005 RF-08) |

   O tracker de Initials QUIC (4096 entradas, 8 MiB, spec 011) fica fora do orçamento, com teto próprio.
3. **Conta de memória.** Pior caso de entrada: 40 MiB do orçamento + 8 MiB do tracker QUIC = 48 MiB, deixando
   ~32 MiB do `GOMEMLIMIT` para o runtime, TLS, quic-go, buffers de saída e as 250 conexões. O padrão cabe no
   perfil do RNF-01 (200 conexões, cabeçalhos de poucos KiB, alguns WebSockets) com folga de uma ordem de
   grandeza; o orçamento só morde sob ataque.
4. **Configuração.** Só o orçamento global é variável (`FS_WEB_INPUT_BUDGET`, no `.env.example` pela tarefa que a
   criar); os tetos por protocolo são constantes. Mudar o `MemoryMax` do web exige rever o padrão.
5. **Sem limite por IP** (ADR 0001): o orçamento é do serviço. Um atacante que o esgota degrada o registro e as
   respostas de quem chega durante o ataque (431, 503, `H3_EXCESSIVE_LOAD`, `fields_truncated`), mas o processo
   não morre e as conexões em andamento continuam.

## Alternativas consideradas
- **Tetos independentes por protocolo** (h1 32 MiB, h3 16 MiB, WebSocket 32 sessões, h2 1 MiB por conexão): cada
  caminho isolado dos outros, mas a soma dos piores casos passa dos 96M; para caber, cada teto ficaria abaixo do
  que o próprio protocolo precisa num pico legítimo, enquanto a capacidade dos outros fica ociosa.
- **Só tetos por conexão** (sem global): não resolve a multiplicação por `FS_MAX_CONNS`, que é a causa de 155 e 136.
- **Baixar `FS_MAX_CONNS` ou subir o `MemoryMax`**: o primeiro tira capacidade do RNF-01 para todos; o segundo
  só muda o número do pior caso, que continua sem teto.
- **Orçamento que bloqueia até haver espaço**: prende a conexão e a goroutine do atacante, que é o que se quer
  liberar; a recusa imediata é mais barata.

## Consequências
- Spec 001 (ameaças), 005 (variável e regra), 009, 010, 011 e 012 atualizadas com os tetos.
- Tarefas: 131 e 133 (tetos do h1, independentes desta), 155 (reserva do cabeçalho h1 e o contador global do
  web), 135 (h2), 134 (h3), 136 (WebSocket e `MAX_CONCURRENT_STREAMS`). A 155 cria o contador e a variável; as
  outras usam o mesmo contador e, se chegarem antes, criam-no com a mesma interface.
- O SETTINGS de saída do h2 passa a anunciar `MAX_CONCURRENT_STREAMS` = 100: muda o que o espelho registra do
  próprio servidor e os goldens que o comparam (tester, task 136).
- O teste de cada caminho prova a devolução da reserva (o contador volta a zero depois de cada conexão, inclusive
  com erro).
