# 0070 — Regra única do orçamento de entrada do cliente anônimo no web e no raw

Status: aceita
Data: 2026-11-22

## Contexto
A ADR 0033 criou o orçamento de entrada do web para "todo caminho que retém bytes recebidos do cliente enquanto
espera o resto", a 0036 passou a reservar a memória alocada (cópias e capacidade) e a 0039 fixou a conta no
finger-01 (`MemoryMax=768M`, `GOMEMLIMIT=512MiB`, orçamento padrão 192 MiB, 1000 conexões, base de ~80 MiB). A
revisão de 2026-11-21 achou o mesmo padrão em 13 caminhos, quase todos medidos, que a regra não alcança porque o
dado não é "byte esperando o resto": é **derivado** dele, é **saída** dimensionada pelo cliente, ou vive no **raw**,
que não tem orçamento:
- 322: `h=` e `status=` repetidos sem teto (5–9 MiB por conexão);
- 323: captura do ClientHello até 256 KiB por conexão, presa pela vida da conexão (web e raw);
- 324: corpo chunked aloca 32 KiB por pedaço (CPU);
- 325: corpo h1 em espera (cru, lista de pedaços, extensões) até ~1,2 MiB por conexão;
- 326: escritor h1 monta `hsize=`/`chunk=` de até 1 MiB por escrita;
- 327: método, versão e `controls` gigantes somem com o evento e custam 0,5–1 s de CPU;
- 328: h2 retém ~5 MiB por conexão depois de um HEADERS de 1 MiB;
- 329: resposta h2/h3 presa no controle de fluxo para sempre, com buffer de 1 MiB por stream;
- 330: cabeçalhos decodificados de streams h2/h3 com corpo pendente (até 100 MiB por conexão);
- 331: streams de controle h3 com frames de 1 MiB sem reserva nem prazo;
- 343: lista de leituras do sink do web, ~420 KiB por conexão;
- 344: nenhum `recover` por conexão no web, e a reserva do `tap` não é devolvida em `defer`.
As tasks 325, 330 e 323 pedem a regra antes da correção.

## Decisão
Complementa as ADRs 0033, 0036 e 0039 (nada nelas é substituído; os tetos e números de lá continuam).

1. **O que a regra cobre.** Toda memória que o web ou o raw retém por conexão, stream ou requisição e que **cresce
   com o que o cliente manda**: os bytes recebidos, as estruturas derivadas deles (campos decodificados, listas de
   controles, pedaços, extensões, leituras, captura de handshake) e os buffers de saída dimensionados por parâmetro
   do cliente. Cada uma é de um de dois tipos:
   - **retenção fixa**: no máximo **32 KiB** por item e **64 KiB** somados por conexão, listada na spec do serviço
     (web: spec 005 RF-12; raw: spec 006). Pior caso com 1000 conexões: 62,5 MiB;
   - **reserva**: reserva do orçamento a capacidade que aloca, antes de alocar (ADR 0036 item 2), e devolve em
     `defer` em qualquer saída (fim, erro, prazo, pânico recuperado).
2. **Sem orçamento**: dado só de análise → para de guardar e marca o `*_truncated` do contrato, sem recusar e sem
   contar em `*_input_budget_denied_total` (como o `tap`, ADR 0036); dado de que o protocolo precisa para seguir →
   recusa com a resposta do protocolo (431 no h1 e no h2, `H3_EXCESSIVE_LOAD` no h3, 503 antes do 101 no WebSocket,
   fechamento antes do handshake no TLS) e conta em `*_input_budget_denied_total`.
3. **Repetição e amplificação têm teto de contagem** antes de acumular: `h=` no máximo **1024** por requisição e
   `status=` 1xx no máximo **16**; o excedente é ignorado e o nome entra em `controls.clamped` (a resposta segue,
   sem 400). No evento, `request_line.method` e `request_line.version` são cortados em **256 bytes** (fronteira de
   runa), com `request_line.method_truncated`/`version_truncated`; `controls.params` e `controls.invalid` caem à
   metade a cada volta do corte do evento, com `controls.truncated`. O valor completo segue nos bytes crus e no
   fluxo `in`.
4. **Saída**: nenhum buffer de escrita passa de **32 KiB**; `hsize=`, `chunk=` e `size=` saem em pedaços de até
   32 KiB de um buffer por resposta (os bytes no fio e o `response_sent` não mudam). Toda escrita que pode bloquear
   pelo cliente tem prazo igual à ociosidade corrente (`idle`), renovado a cada escrita que progride: h1 como hoje;
   h2 e h3 por stream (vencido, o stream termina com RST_STREAM/`CancelWrite`, o `hold` é solto e o registro sai).
   Os atrasos pedidos (`delay_head`, `delay_body`) continuam valendo.
5. **CPU**: nenhuma alocação proporcional a um buffer fixo por unidade de entrada (buffer de cópia do corpo uma vez
   por `Reader`; no máximo ~3 alocações pequenas por pedaço chunked); laços de corte saem quando uma volta não
   reduz o tamanho.
6. **Robustez**: toda goroutine por conexão ou stream (web: `Serve`, `requestConnID`, h3, WebSocket; raw: sessão)
   tem `recover`, que registra o pânico com a pilha (`log.Error`), conta em `web_panics_total`/`raw_panics_total`
   (heartbeat) e fecha só aquela conexão; as reservas (inclusive a do `tap`) são devolvidas em `defer`.
7. **Caminhos do web** (aplicação da regra):

   | Caminho | Tipo | Teto | Sem orçamento |
   | --- | --- | --- | --- |
   | captura do ClientHello (323) | reserva até o fim do handshake | mensagem remontada ≤ `MaxClientHelloLen` (64 KiB) + registros crus ≤ 16 KiB (`client_hello_truncated` acima), cópia exata no corte; solta depois de publicar o ClientHello | fecha antes do handshake |
   | corpo h1: cru inline, lista de pedaços, extensões (325) | reserva pela requisição | os da spec 009 RF-03 | para de guardar, `body.raw_truncated`/`chunks_truncated` |
   | bloco HEADERS + CONTINUATION do h2 em montagem (328) | reserva | 1 MiB | o parser para o HPACK (`killHPACK`), `fields_truncated` |
   | buffers do parser h2 e `readBuf` do x/net (328) | fixa | `MaxReadFrameSize` **16 KiB** anunciado; buffers acima de 32 KiB soltos depois do frame | — |
   | cabeçalho decodificado de stream h2/h3 até o `publish` (330) | reserva, num hold por conexão de 2 MiB (o mesmo do HEADERS h3 em espera) | 2 MiB por conexão | h2: 431 na hora; h3: `H3_EXCESSIVE_LOAD`; decodificado acima de 1 MiB (`MAX_FIELD_SECTION_SIZE`) também |
   | frames do stream de controle h3 (331) | reserva | 64 KiB por frame; só o primeiro stream de controle é analisado | o segundo stream de controle fecha a conexão com `H3_STREAM_CREATION_ERROR` (0x0103, RFC 9114 §6.2.1) |
   | `reads_in` do sink (343) | fixa até 1024 entradas (`[2]float64`, 16 KiB), reserva acima, até 8192 | 8192 | `reads_in_truncated` |
   | controles `h=`/`status=` (322) | teto de contagem (item 3) | 1024 / 16 | — |

   O `MaxHeaderBytes` do h2 fica em 1 MiB (paridade com a spec 009 RF-10), porque o decodificado passa a reservar.
8. **Raw**: ganha um orçamento interno constante de **64 MiB** (sem variável), com gauge
   `raw_input_budget_used_bytes` e contador `raw_input_budget_denied_total` no heartbeat. Reservam: a captura do
   ClientHello (mesmo teto e mesma soltura do web; sem orçamento, fecha antes do handshake, exceção à spec 006 RF-07
   como as recusas do web) e `reads_in`/`writes_out` acima das 1024 primeiras entradas (sem orçamento,
   `*_truncated`). Conta (`GOMEMLIMIT=192MiB`): 64 MiB do orçamento + 1000 × 32 KiB das listas fixas + a base.
9. **Conta da ADR 0039 item 4**: a parcela Go passa a ser base ~80 MiB + retenção fixa ≤ 62,5 MiB + tracker QUIC
   8 MiB + orçamento 192 MiB = 342,5 MiB ≤ 512 MiB. As metas medidas da carga do orçamento não mudam.

## Alternativas consideradas
- **Corrigir cada caminho com um teto local**: foi o que gerou 13 caminhos fora da conta; sem regra, o próximo
  parser repete o erro.
- **Orçamento por IP**: contraria a ADR 0001 (sem limite por IP) e não cobre origens falsificadas no UDP.
- **Prazo do corpo da requisição em h2/h3 em vez da reserva do decodificado** (330): limita o tempo, não a memória
  simultânea.
- **Variável `FS_RAW_INPUT_BUDGET`**: o raw não tem perfil de uso que peça ajuste; constante basta e evita mais uma
  chave.
- **400 para `h=` repetido demais**: mudaria a resposta de um pedido válido por um teto do espelho; ignorar o
  excedente com `clamped` segue a regra dos outros controles.

## Consequências
- Specs 005 (RF-07, RF-12), 006 (RF-06, RF-07), 008 (RF-02), 009 (RF-03), 010 (RF-05a) e 011 (Memória)
  atualizadas; openapi 0.7.0 com `method_truncated`, `version_truncated` e `controls.truncated` (asyncapi 0.7.0). Aplicado por delegação (specs/002, ADR 0023) pelas tarefas de implementação, junto com o código, porque os testes de contrato exigem struct e casos; o bloco exato fica nas tarefas.
- O SETTINGS do h2 do espelho passa a anunciar `MAX_FRAME_SIZE` 16384 (o padrão do protocolo): muda o que o espelho
  registra de si mesmo e os goldens que o comparam (tester).
- Tarefas: 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 343 e 344 (implementer-web; a parte do raw da 323 e o
  item 8, implementer-raw). Cada caminho com reserva tem teste de que a reserva ≥ 90% do retido e de que o contador
  volta a zero (ADR 0036).
