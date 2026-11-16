# 0041 — Ingest atrasado: relógio de captura nos prazos, lacunas do stream visíveis e RNF-01 400/100 mantido

Status: aceita (item 1, RNF-01 400/100 mantido: substituído por 0042, que recua para 200/50 com os degraus; 400/100 de volta pela 0046)
Data: 2026-11-15

## Contexto
A primeira carga oficial no finger-01 (task 235, janela `official-f01a`, `v0.2.1-75-g1f83ec0`, perfil 400/100 da
ADR 0039) falhou: feed p99 60 s, registro p95 TCP 58 s e QUIC 152 s, 38 657 de 60 000 probes sem registro,
expurgo "0 presentes". O store ficou ~55–60 s atrás do relógio desde o 1º minuto, com 78% de um núcleo de média
(cota 400%, `nr_throttled` 0). `/jsz` mostrou ~1,14 M mensagens do `FS_EVENTS` expiradas (`max_age` 60 s) sem
entrega, invisíveis em `dropped_events_total`, nas métricas do store e no health. `fs_store_stray_packets_total`
cresceu ~450/s (Δ 269 060 na janela). Na task 215 (janela A4), ~4 660 fluxos ficaram abertos no store sem FIN/RST
e sem socket no servidor, segurando o modo degradado até a ociosidade de 630 s.

Leitura do código (`internal/store/ingest.go`, `flows.go`, `correlate.go`, na `main` em `fc27f27`):
1. **Prazos dos fluxos comparam relógios diferentes.** `Run` chama `flows.due(in.now())` (relógio de parede do
   store) a cada lote, e `due` compara com `c.lastSeen` (instante de captura do pacote):
   `now-c.lastSeen > idle`. Com o ingest atrasado mais que o prazo, o fluxo vence assim que é criado:
   - TCP sem o ACK do handshake usa `halfOpenIdle` (10 s). Com atraso > 10 s, quando o ACK do handshake cai num
     lote seguinte ao do SYN, a conexão é finalizada no fim do lote do SYN; os pacotes seguintes da 5-tupla não
     acham entrada, abrem um fluxo novo sem SYN (`handle` cria conexão para qualquer pacote não RST), que tem
     `synAck == 0`, vence de novo no lote seguinte e vira **pacote avulso** (`isStray`), e assim a cada lote.
   - Fechados por FIN entram em `closed` e, no mesmo `due`, saem dele (`now > lingerUntil + lateKeep`, 12 s depois
     do último pacote): o ACK final e o RST tardio viram fragmento novo e avulso, em vez de tardio.
   - UDP antes do evento h3 usa 30 s: com ~55 s de atraso todo fluxo QUIC vence no fim de cada lote e se parte
     (registro QUIC p95 de 152 s); conexões só de eventos (`eventOnlyIdle`, 30 s, contra o `ts` do evento) são
     esquecidas a cada lote.
   - O mesmo vale, com prazos maiores, para o QUIC com evento h3 (`FS_IDLE_DEFAULT` + 30 s) e o TCP estabelecido
     (630 s).
   Resultado: registros sem fechamento nem eventos, avulsos aos milhares, eventos sem conexão aberta (fila
   pendente, `locate` no banco, conexões só de eventos: Δ 4 082) e trabalho de finalização (ler `packets`, montar
   pcap, apagar) por fragmento.
   É realimentação positiva: abaixo de ~10 s de atraso o custo por pacote é o medido na `official-50k`; acima, ele
   se multiplica e o store não volta enquanto a carga dura. O atraso para em ~60 s só porque o JetStream descarta
   o que passa do `max_age`. No pré-aquecimento o processo ficou em 100% de um núcleo; na janela, a média de 78%
   inclui o tempo em que o laço espera o `Fetch`.
2. **O caminho é serial, mas não foi isso que derrubou a carga.** Um escritor SQLite (`SetMaxOpenConns(1)`, WAL,
   `synchronous=NORMAL`, sem fsync por commit), lotes de até 64 mensagens, índices presentes nas consultas por
   5-tupla, expurgo limitado a 100 ms/s. Não há consulta, trava ou fsync por pacote que explique sozinho a queda;
   a vazão do ingest acima de 50/s nunca foi medida sem a realimentação acima, então o teto real é desconhecido.
3. **Lacunas do stream não são vistas.** O consumidor recebe as mensagens em ordem de sequência; as expiradas
   (`max_age` ou `max_bytes` com `DiscardOld`) aparecem só como salto de `Sequence.Stream` no metadado, que o
   store não lê. Nada no health ou em `/metrics` acusa atraso do consumidor.
4. **Fluxos presos.** Um fluxo TCP estabelecido cujo FIN/RST expirou no stream só sai pela ociosidade de 630 s
   (`tcpIdle`) e conta como viva no modo degradado. Não há outro caminho de perda de pacotes antes do store com
   `kernel_drops`, `dropped_events_total` e `fs_store_flows_dropped_total` em 0; e o defeito do item 1 fecha
   fluxos cedo, não os prende. A causa provável dos ~4 660 fluxos da 215 é, portanto, a expiração.

## Decisão
1. **RNF-01 fica em 400/100** (ADR 0039 item 5, ainda provisório pelo item 6). A falha tem causa pontual e clara
   (item 1 do contexto), não uma medida do teto do caminho serial. A release `v0.3.0` espera a correção e uma nova
   carga oficial (task 235). Se, corrigido o relógio, a carga ainda falhar por vazão (store saturando um núcleo
   sem realimentação), aplica-se a ADR 0039 item 6: ADR nova volta o RNF-01 para 200/50 com a medida, e a
   otimização do ingest fica para depois da release. Para isso a 235 mede antes o teto em degraus.
2. **Relógio de captura nos prazos do ingest.** Todo prazo do ingest que se compara a um instante de captura (de
   pacote ou de evento) usa o relógio de captura do ingest, nunca o relógio de parede:
   `C = min(parede, T + (parede − P))`, onde `T` é o maior instante de captura já processado (pacotes e eventos) e
   `P` o instante de parede em que ele foi processado. Com o ingest em dia, `C` ≈ parede; atrasado, `C` anda com o
   stream; sem tráfego, `C` anda com a parede (as ociosidades vencem normalmente). Valem por `C`: ociosidade do TCP
   meio-aberto, do estabelecido, do UDP e do QUIC; `closeAt` (folga de fechamento); a permanência dos fechados à
   espera de tardios; a ociosidade das conexões só de eventos; a validade das reservas de `conn_id` quando
   comparada a `ts`. Ficam no relógio de parede: a espera de 2 s da fila pendente (conta desde a chegada),
   `updated_ns`, os `ts` de decisão do feed (ADR 0025) e os histogramas de atraso (`ingest_lag`,
   `record_ready`), que medem justamente o atraso. Valores dos prazos sem mudança.
3. **Lacuna e atraso visíveis** (spec 004 RF-09 e "Métricas"):
   - `fs_store_stream_lost_total` (contador): mensagens do `FS_EVENTS` que nunca chegaram ao store, pela soma dos
     saltos de `Sequence.Stream` no metadado das mensagens recebidas (salto = seq − (maior seq visto + 1), só
     quando positivo; reentrega não conta). Na partida, a primeira mensagem não conta salto.
   - `fs_store_ingest_backlog_seconds` (gauge): parede − instante de publicação no stream da última mensagem
     processada (o que falta para o consumidor alcançar o stream), e `fs_store_ingest_pending_messages` (gauge):
     `NumPending` do metadado da última mensagem.
   - Health do store `degraded`, com motivo, enquanto `fs_store_ingest_backlog_seconds` > **5 s** (motivo
     `ingest backlog <n>s`) e por 5 min depois de qualquer crescimento de `fs_store_stream_lost_total` (motivo
     `stream lost <n> messages in 5m`). O `ok` do health agregado continua sendo "todos up" (não muda).
4. **Fluxos depois de uma lacuna.** Ao detectar um salto (item 3), o ingest marca como suspeitos os fluxos abertos
   cujo último pacote é anterior ao instante de publicação da mensagem que revelou o salto. Fluxo suspeito usa a
   ociosidade de 10 s (a do meio-aberto, pelo relógio `C`) em vez da do estabelecido ou do QUIC; um pacote novo
   tira a marca. Fechado assim, sai como hoje por ociosidade (`close.how` `timeout`, `reason` `idle`), sem campo
   novo. Uma conexão legítima ociosa que atravessou a lacuna pode fechar cedo e, se voltar a falar, virar
   fragmento: aceito, porque o registro dela já perdeu pacotes e a perda agora aparece no health.
5. **Avulsos de meio de fluxo contados à parte.** `fs_store_stray_midflow_total` (contador): pacotes TCP que viram
   avulsos num fluxo cujo início o store não viu (sem SYN nem SYN-ACK no fluxo, e o pacote não é RST). Com o
   ingest em dia e sem lacuna, só o tráfego alheio (varreduras, sessões longas de antes da partida) o faz crescer.
   `fs_store_stray_packets_total` continua contando todos.
6. **Carga oficial** (spec 017 RF-13; ADR 0022 e 0039 item 6 com estas metas a mais): `fs_store_stream_lost_total`
   sem crescer; health do store sem `ingest backlog` nem `stream lost` na janela; registrar sem meta
   `fs_store_stray_midflow_total` e `fs_store_stray_packets_total` por segundo, `fs_store_ingest_backlog_seconds`
   máximo. Antes da janela oficial, degraus de 3 min a 50, 75 e 100 novas/s (simultâneas proporcionais) para
   registrar o teto do ingest (CPU do store, backlog, lost) sem meta.

## Alternativas consideradas
- **Voltar já a 200/50** — a carga não mediu o teto, mediu a realimentação; a `official-50k` em 200/50 só passou
  porque o atraso nunca chegou aos 10 s. O defeito do relógio derruba também 200/50 depois de qualquer pausa de
  mais de 10 s (expurgo longo, checkpoint, reinício do store com backlog), então a correção é obrigatória de
  qualquer forma.
- **Aumentar `max_age` do stream** — esconde o sintoma por mais tempo e aumenta a memória do nats; com o relógio
  errado, o atraso continuaria crescendo até o novo teto.
- **Prazos só pelo instante de captura (sem a parede)** — sem tráfego nada venceria: conexões ociosas ficariam
  abertas até o próximo pacote de qualquer fluxo.
- **Ler a lacuna pelo `ConsumerInfo` a cada segundo** — mais uma ida ao servidor por segundo e só uma aproximação
  (`stream first_seq` contra o `ack_floor`); o salto de sequência no metadado é exato e de graça.
- **Paralelizar o ingest agora** (várias transações, várias conexões de escrita) — mudança grande sem medida que a
  peça; fica para a tarefa de otimização se o item 1 da decisão disparar o recuo.

## Consequências
- Código (implementer-store): `flows.go`, `ingest.go`, `correlate.go`, `health.go`, `metrics.go`; testes com
  atraso simulado (relógio de parede adiantado) e lacuna de sequência.
- Spec 004 (RF-09, "Comportamento", "Métricas") e spec 017 RF-13 atualizadas; contratos sem mudança (`reasons` é
  lista livre de texto; métricas não estão no openapi).
- A carga oficial 235 roda de novo depois das tasks 242–245 implantadas; a release 236 depende delas.
- O relógio `C` vira a referência de "agora" do ingest para tudo que é instante de captura; código novo que
  compare prazos com `ts` usa `C`.
