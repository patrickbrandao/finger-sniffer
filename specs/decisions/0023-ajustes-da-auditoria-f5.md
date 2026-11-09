# 0023 — Ajustes da auditoria F5 (agrupados)

Status: aceita
Data: 2026-11-09

## Contexto
A auditoria spec × implementação da F5 (task 071, reviewer) achou divergências que não são defeito de código: a
spec pedia algo inalcançável, ambíguo ou diferente do que se decidiu fazer, ou o processo não previa o que de fato
aconteceu. Fatos novos, todos medidos ou conferidos na vps602 em 2026-11-09:
1. **Relógio TSval**: o macOS (`net.inet.tcp.randomize_timestamps=1`) desloca o TSval por conexão e o Linux
   (`tcp_timestamps=1`, kernel ≥ 4.10) por par de endereços. Três `nc` seguidos do mesmo Mac deram três grupos
   (`ts_initial` 2393376766 / 3488726338 / 2355500153). O CA "duas conexões do mesmo host por IPs diferentes são
   mesmo relógio" é inalcançável com clientes modernos.
2. **Fechamento do WebSocket**: depois de um close iniciado pelo cliente, o web fecha o TCP primeiro, como manda a
   RFC 6455 §7.1.1 ("the server SHOULD close the underlying TCP connection first"), o que contraria a letra da
   spec 005 RF-08.
3. **SETTINGS h2 com id repetido**: o `x/net/http2` (sem fork, ADR 0009) responde GOAWAY PROTOCOL_ERROR e não
   processa os HEADERS; o parser passivo guarda a ordem com as repetições.
4. **`conn=close`** só escreve `Connection: close`; a RFC 9112 §9.6 manda o servidor fechar depois da resposta, o
   que a spec 005 RF-08 proíbe.
5. **Métricas do capture**: o heartbeat (spec 001) leva métricas sem rótulos; o código expõe
   `fs_capture_packets_in_total`/`_out_total`, não `fs_capture_packets_total{dir}`.
6. **Endereços**: a ADR 0001 diz "listeners só nos IPs públicos da eth0"; web e dns seguem; raw e a API do store
   escutam em `*` (tasks 082, 083).
7. **Dependências**: `github.com/libdns/libdns` (tipo da interface de provedor do certmagic, liberada pelo humano
   no brief da F3–F5) e `github.com/prometheus/client_model` (tipo de retorno de `prometheus.Gatherer.Gather`,
   usado em `internal/store/metrics_test.go`) estão diretas no `go.mod` sem constar da ADR 0009.
8. **Processo**: 56 de 60 PRs foram mergeados sem revisão do reviewer; a 073 (implementer-web) aplicou no openapi
   um bloco decidido pelo architect na task 064 e alterou `pkg/event` (do store); pastas sem dono na spec 002
   (`internal/version/`, `redocly.yaml`, `CLAUDE.md`, `.claude/agents/**`, `changes/`); a spec cita um
   `.gitattributes` que não existe mais (removido na task 040).
9. **Verificação**: fuzz de 60 s pedido nas specs 008/009/010 × 10 s por alvo na 017 e no `scripts/verify.sh`; o
   quick roda o `release-test` (build dos 5 binários) quando `Makefile`/`scripts/release*` mudam; a cobertura
   total exclui `cmd/`.
10. **UDP**: registros UDP puros sem `times`, QUIC com `times` só com `tls_done`; fluxos UDP da porta 53 ficam
    `proto=udp` sem probe.

## Decisão
1. **Relógio TSval** (spec 013 RF-10): `ts_clock_group` junta conexões cujo TSval é explicado por um único relógio
   (mesma frequência e mesmo deslocamento extrapolado, dentro da tolerância); clientes que deslocam o TSval por
   conexão ou por par de endereços ganham grupos distintos, e isso é o esperado, não erro. O CA passa a ser:
   mesmo relógio sem deslocamento por IPs diferentes → mesmo grupo (pcap sintético); Linux pelo mesmo par de IPs →
   mesmo grupo; macOS → grupos distintos.
2. **WebSocket** (spec 005 RF-08, spec 012 RF-06): exceção explícita. Depois da troca de closes do WebSocket o
   espelho fecha o TCP primeiro (RFC 6455 §7.1.1). `websocket.close.by` diz quem iniciou o fechamento; `close.by`
   do registro TCP diz quem mandou o primeiro FIN. O close de resposta fica só em `frames[]` (contrato 0.3.3).
3. **SETTINGS repetidos** (spec 010): o esperado é o registro com a ordem e as repetições, o GOAWAY
   PROTOCOL_ERROR do servidor em `frames` e nenhum `streams[]`. Não se troca de biblioteca por isso.
4. **`conn=close`** (spec 005 RF-07): só escreve o campo; a conexão segue até `idle` ou até o cliente fechar,
   para observar se o cliente (ou o proxy) obedece. É um desvio deliberado da RFC 9112 §9.6, coerente com RF-08.
   Para o servidor fechar, usa-se `close=after`.
5. **Métricas do capture** (spec 003): valem os nomes do código, `fs_capture_packets_in_total` e
   `fs_capture_packets_out_total` (métricas do heartbeat não têm rótulos); a task 079 não renomeia.
6. **Endereços** (ADR 0001): a regra vale para **todo listener que recebe tráfego de fora**, inclusive a API
   9000/9001 e o raw: escutam em `FS_LISTEN_IPV4`/`FS_LISTEN_IPV6`. A API escuta também em `127.0.0.1` (diagnóstico
   local por ssh). `FS_RAW_LISTEN_HOST` pode ficar só como sobreposição para testes (vazio = IPs públicos). NATS
   segue só em `127.0.0.1`.
7. **Dependências** (ADR 0009): um módulo cujo tipo aparece na API pública de uma dependência permitida e que já
   vem com ela no `go.mod` conta como parte dela e pode ser importado direto para usar essa API. Entram assim
   `github.com/libdns/libdns` (certmagic) e `github.com/prometheus/client_model` (client_golang). Qualquer outro
   módulo continua exigindo o humano.
8. **Processo** (spec 002, ADR 0014):
   - **Revisão no modo autônomo**: quando o humano autoriza trabalho autônomo com merge a cada etapa (como na
     noite de 2026-11-08 para 09: "a cada etapa faça commit/merge/push"), o PR é mergeado com o CI verde sem
     esperar o reviewer; a revisão passa a ser a auditoria do conjunto pelo reviewer antes da release (task 071)
     e a revisão do PR de release (task 072). Fora desse modo, o merge exige a revisão do reviewer registrada no
     próprio PR (`gh pr review --comment` ou comentário com o veredito). Os 56 PRs mergeados sem revisão ficam
     cobertos pela auditoria da 071.
   - **Delegação de contrato**: um papel só altera arquivo de outro (contrato, spec, `pkg/` alheio) quando a
     tarefa escrita pelo architect lista o arquivo em `arquivos` e traz o bloco ou a decisão exata; o PR cita a
     tarefa. Foi o caso da 073 (bloco do `h3_control_stream_seen` decidido na 064). Sem isso, vale a regra geral.
   - **Donos**: `internal/version/` → infra (preenchido por `-ldflags` no Makefile); `redocly.yaml` → infra
     (ferramenta do verify); `CLAUDE.md` e `.claude/agents/**` → architect; `changes/task-NNN.md` → quem entrega a
     tarefa, juntado e removido pelo architect; `README.md` → docs (já na tabela). A linha `.gitattributes` sai da
     spec 002.
9. **Verificação** (specs 008/009/010/017): fuzz de **10 s por alvo** no `verify-full` (inclusive no CI) e de
   **60 s por alvo antes de cada release** (`FS_FUZZ_TIME=60s make verify-full`), registrado no PR de release; a
   auditoria F5 já rodou os 60 s em 008/009/010/011. O quick roda o `release-test` quando `Makefile` ou
   `scripts/release*` mudam (exceção à spec 017 RF-04: é o único teste desses arquivos e leva ~10 s). A cobertura
   total (≥ 60%) não conta `cmd/` (funções `main`, cobertas pelo e2e).
10. **UDP** (spec 013 RF-01, spec 004): em UDP o primeiro datagrama é o `started` do resumo e o fim é o `ended`;
    `times` é da linha do tempo TCP e, em UDP, só aparece com camada QUIC (`tls_done`). Fluxos UDP da porta 53
    ficam `proto=udp` e sem probe: a consulta vive em `/api/v1/dns` (com `probe_id`), e ligá-la ao fluxo UDP do
    resolvedor faria o long-poll de `/probes` esperar a ociosidade UDP. A regra `dns` = fluxo da 53 com `dns.query`
    é só para TCP.

## Alternativas consideradas
- Mandar o web esperar o FIN do cliente depois do close do WebSocket: contraria a RFC 6455 e deixa conexões
  presas a clientes que não fecham o TCP.
- `close` do WebSocket com os dois lados no contrato: mexe em web, store e `pkg/event` antes da v0.1.0 para um
  dado que, quando o cliente inicia, vem do próprio espelho.
- Renomear as métricas do capture para `{dir}`: exige rótulos no heartbeat, sem ganho para o xProxy.
- Remover o `client_model` do teste: obrigaria a reimplementar o leitor do formato de exposição só para fugir de
  um tipo que a própria API permitida devolve.
- Exigir a revisão do reviewer em cada PR mesmo no modo autônomo: com ninguém para revisar a noite toda, nada
  seria mergeado, contra a instrução do humano.

## Consequências
- Specs 002, 003, 004, 005, 008, 009, 010, 012, 013 e 017 ajustadas; ADRs 0001, 0009 e 0014 apontam para esta.
- Tasks 079 (métricas), 082 (API nos IPs públicos + 127.0.0.1) e 083 (raw nos IPs públicos) seguem esta decisão.
- `docs/probes.md` e `docs/api.md` precisam descrever os itens 1–4 e 10 (task de docs).
- Nenhuma mudança de contrato além da 0.3.3 (task 086).
