# 0034 — Tetos de recursos e caminhos de falha do store (auditoria de 2026-11, agrupados)

Status: aceita
Data: 2026-11-14

## Contexto
A auditoria de 2026-11-10 achou, no store (1 vCPU, `MemoryMax=384M`), recursos que crescem com a entrada de um
cliente anônimo e caminhos de erro sem regra escrita:
- **128**: a tabela de fluxos não tem teto e é varrida a cada conexão nova; um SYN flood de origens que não
  respondem enche a tabela (cada entrada vive `idle` + 30 s = 150 s) e satura a vCPU.
- **137**: depois de `FS_PCAP_MAX_BYTES_PER_CONN` o pcap guarda "só cabeçalhos" sem teto de registros.
- **138**: a fila do tempo real é limitada em eventos (`FS_LIVE_BUFFER`), não em bytes; 64 clientes lentos com
  eventos de ~900 KiB passam do `MemoryMax`. O WebSocket já encerra o cliente que não lê em 30 s; o SSE não, e a
  ADR 0020 rejeitou "desconectar o cliente lento".
- **141**: o registro de grupos de relógio TSval (spec 013 RF-10) cresce sem teto e é varrido linearmente.
- **139/157**: falha de transação no ingest não desfaz a tabela de fluxos; erro depois do commit vira `Nak` e
  duplica o lote; erro de SQL de pacote é engolido como "lote ruim".
- **140**: evento de uma conexão apagada (expurgo ou `DELETE`) volta em `Nak` em laço.
- **150**: `DELETE /api/v1/probes/{id}` não apaga as conexões ainda abertas, que reaparecem quando fecham.
- **151**: o store fecha TCP ocioso em `FS_IDLE_DEFAULT` + 30 s, mas o web aceita `idle=` até `FS_IDLE_MAX`
  (600 s); uma conexão legítima com `idle=300` é fechada no store antes do web.
- **154**: o expurgo por tamanho só apaga `connections`; `dns_queries` e `stray_packets` crescem até o teto.
- **176**: `record_json` de uma conexão aberta é o da criação; a lista pode mostrar `requests` parado.
- **182**: o store não confere `Fs-Format`/`Fs-Schema-Version` antes de decodificar o lote FSPB.
- **184**: `FS_MAX_CONNS=0` (documentado: "degrada tudo" no store) derruba o web, que lê o mesmo env.

## Decisão
1. **Tabela de fluxos com teto (128).** No máximo **8192** entradas (constante). TCP que não completou o
   handshake (sem o ACK do cliente depois do SYN-ACK) tem ociosidade de **10 s**, não `idle` + 30 s. Com a tabela
   cheia, uma 5-tupla nova **despeja a entrada não estabelecida mais antiga** (TCP sem handshake completo ou UDP
   não-QUIC sem resposta), sem gravar registro nem avulso dela; sem entrada a despejar, a 5-tupla nova é recusada:
   seus pacotes não criam conexão, linha em `connections`, `packets` nem `stray_packets`. Os dois casos contam em
   `fs_store_flows_dropped_total{reason=evicted|table_full}`. A contagem de vivas do modo degradado (ADR 0026)
   continua a mesma, agora limitada pela tabela. Sem limite por IP (ADR 0001).
2. **Ociosidade do TCP estabelecido (151).** `max(FS_IDLE_DEFAULT, FS_IDLE_MAX)` + 30 s (630 s com os padrões),
   para nunca fechar no store uma conexão que o web ainda mantém por `idle=`. Não estabelecidas seguem o item 1;
   QUIC e UDP como hoje. Entra depois do item 1, que limita o custo de entradas longas.
3. **Pcap truncado com teto (137).** Depois de `FS_PCAP_MAX_BYTES_PER_CONN`, os registros "só cabeçalhos" têm um
   orçamento próprio de mais `FS_PCAP_MAX_BYTES_PER_CONN` bytes; esgotado, o pacote não entra em `packets` (a
   análise IP/TCP já rodou). `pcap_truncated` e `truncated` corretos também na recuperação de órfãs do reinício.
4. **Tempo real com teto de bytes (138).** Além de `FS_LIVE_BUFFER` eventos, cada cliente enfileira no máximo
   **4 MiB** e o hub, somando todas as filas, **64 MiB** (cada evento conta por fila em que está). Acima, o evento é
   descartado para aquele cliente e conta no `stream.dropped`, como a fila cheia (ADR 0020). **O SSE continua sem
   prazo de escrita** (ADR 0020 mantida: o teto de bytes limita a memória sem desconectar). O WebSocket mantém o
   prazo de escrita de 30 s que já tem, porque o `coder/websocket` exige prazo por escrita; a diferença entre os
   transportes fica registrada aqui e na spec 004. Sem mudança de contrato.
5. **Grupos de relógio (141).** Janela de **20 min** e no máximo **4096** grupos em memória, despejando o usado há
   mais tempo; `ts_clock_group` é de melhor esforço sob carga.
6. **Falha de transação no ingest (139, 157).**
   - Erro de SQL em qualquer item do lote aborta a transação inteira (rollback) e o lote volta por `Nak`; só lote
     FSPB malformado (`ErrShortBatch` ou cabeçalhos do item 10) é descartado com `Ack` e conta em
     `store_bad_batches_total`.
   - O rollback desfaz também o efeito na tabela de fluxos: conexões criadas pelo lote ficam marcadas para
     reinserção na reentrega (o `INSERT … ON CONFLICT DO UPDATE` já é idempotente).
   - Finalização (gravar o registro e o pcap): as conexões que fecharam no lote só saem da fila de finalização
     depois do commit; falha → nova tentativa uma a uma, até **5**; esgotadas, a linha é fechada com `ended_ns` e o
     que houver. Métricas `fs_store_ingest_errors_total` e `fs_store_finalize_retries_total`.
   - **Erro depois do commit nunca vira `Nak`** (o lote já está gravado): registra em log e confirma com `Ack`.
   - A retenção também expurga linhas com `ended_ns` nulo que não estão mais na tabela de fluxos e são mais velhas
     que `FS_RETENTION` + a ociosidade máxima do item 2.
7. **Evento de conexão apagada (140).** Se o alvo de um evento não existe mais no banco, o evento segue a regra de
   evento sem conexão (spec 004: espera até 2 s e cria a conexão só com eventos), salvo o caso do item 8. **Sem
   `MaxDeliver`/`BackOff`** no consumidor: a semântica de entrega da ADR 0016 fica como está.
8. **`DELETE` de probe (150).** Numa transação: apaga todas as conexões do probe, **abertas** ou fechadas (com as
   filhas), as consultas DNS e a linha do probe; tudo some na hora de todas as leituras (`/probes/{id}`,
   `/connections?probe=`, leitura direta, tempo real). O ingest guarda em memória os `conn_id` das que estavam
   abertas (ou à espera da finalização) e descarta os pacotes, os eventos e a finalização delas, sem recriar a
   linha, até a conexão fechar. Tráfego novo com o mesmo probe ID depois do `DELETE` cria um probe novo.
   *Ajuste de 2026-11-14 (task 216):* o texto original apagava a linha da conexão aberta só no fechamento; a
   implementação (PR #168) apaga na hora, na mesma transação. O efeito na API é o mesmo e nada se perde (o
   cliente pediu o apagamento), com uma linha a menos para filtrar em cada leitura; o texto foi alinhado.
9. **Expurgo por tamanho (154).** O laço de `FS_STORE_MAX_BYTES` apaga, do mais antigo para o mais novo,
   `connections` (com as filhas), `dns_queries` e `stray_packets`, e só desiste quando nada mais pode ser apagado.
10. **Cabeçalhos do lote FSPB (182).** Antes de decodificar, o store confere `Fs-Format: fspb1` e
    `Fs-Schema-Version: 1`; divergência → lote descartado (`Ack`), contado em `store_bad_batches_total` com o
    motivo no log. `Fs-Count` diferente do número de registros decodificados → aviso e
    `store_batch_count_mismatch_total`, o lote é usado. Complementa a ADR 0015 (`fspb2` conviveria por subject ou
    cabeçalho, e o store v1 o rejeitaria em vez de decodificar errado).
11. **Registro de conexão aberta (176).** `record_json` de uma conexão aberta é o da criação (ou da última vez que
    `proto`/`probe` mudaram); a API sobrepõe o estado ao vivo da tabela de fluxos em toda leitura de conexão
    aberta (lista e detalhe). Sem migration.
12. **`FS_MAX_CONNS=0` (184).** O valor `0` só tem significado no store (ADR 0027: degrada tudo, sem janela). O web
    (e o raw, ADR 0035) trata `FS_MAX_CONNS` ≤ 0 como o padrão do serviço (250), com aviso no log, em vez de
    recusar a subida.

## Alternativas consideradas
- Tabela de fluxos ilimitada com varredura incremental: tira o custo O(N), mas não a memória nem as linhas de lixo.
- Recusar sempre a 5-tupla nova com a tabela cheia: 820 SYN/s cegariam o espelho para todo cliente legítimo;
  despejar primeiro o meio-aberto preserva quem completa o handshake.
- Gravar os despejados como avulsos: transfere o custo do flood para o SQLite.
- Prazo de escrita também no SSE (fecharia o cliente lento como o WS): contraria a ADR 0020 sem fato que o exija,
  porque o teto de bytes já limita a memória; fica para uma ADR futura se a medição da task 138 mostrar o
  contrário.
- `MaxDeliver`/`BackOff` no consumidor (140): defesa genérica, mas descartaria lotes de pacotes legítimos depois de
  uma falha passageira do SQLite; o laço tem causa conhecida e correção local.
- `DELETE` que espera as conexões abertas fecharem, ou que responde 409: o cliente não controla o fim das
  conexões alheias ao seu teste; apagar na hora e descartar o resto em memória dá o efeito esperado.
- Variável própria para o web em vez da regra do zero (184): mais uma chave para o mesmo conceito.

## Consequências
- Spec 004 (RF-04, RF-06, RF-08, RF-11, Comportamento, Métricas, Dados), 013 (RF-10) e 001 (ameaças) atualizadas.
- Métricas novas: `fs_store_flows_dropped_total{reason}`, `fs_store_ingest_errors_total`,
  `fs_store_finalize_retries_total`, `fs_store_batch_count_mismatch_total`; entram em `docs/metrics.md` (task 188).
- Muda o comportamento sob carga: SYN sem resposta vira avulso em 10 s (antes 150 s), e o `reason=idle` de
  `fs_store_record_ready_seconds` deixa de incluir esses casos depois de 150 s.
- Tarefas: 128, 137, 138, 139, 140, 141, 150, 151, 154, 157, 176, 182 (store) e 184 (web).
