# 0068 — `DELETE` de probe em lotes, com as leituras filtradas na hora

Status: aceita
Data: 2026-11-22

## Contexto
A ADR 0034 item 8 decidiu apagar o probe "numa transação": todas as conexões (abertas ou fechadas, com as filhas
em cascata), as consultas DNS e a linha do probe, para que tudo suma na hora de todas as leituras. Ela é de
2026-11-14. Depois, a F7 (ADR 0043, task 248) fixou que nenhum comando do escritor único pode passar de um passo
curto: o expurgo virou lotes de 100 conexões com passo adaptativo de 25 ms. O `DELETE` de probe ficou de fora. A
task 339 mediu: com 2500 conexões, o `DELETE` levou 172 ms e o ingest esperou 171 ms (p50 sem ele: 0,7 ms); a
100 novas/s por 10 min (60 000 conexões num probe) a parada chega a ~4 s, com o health `degraded`. O tamanho de um
probe não tem teto (a ADR 0032 limita só a resposta do `GET`). Este é o fato novo.

## Decisão
Ajusta a ADR 0034 item 8. O efeito para o cliente fica o mesmo: depois do `204`, nenhuma leitura devolve conexão
nem consulta do probe.
1. **Transação curta no `DELETE`.** Grava uma linha em `deleted_probes(probe_id, conn_cut, dns_cut, deleted_ns)`
   (nova tabela do store, migration do implementer-store aprovada pelo architect no PR), em que `conn_cut` é o maior
   `conn_id` (ULID, ordenado pelo tempo) e `dns_cut` o maior `rowid` de `dns_queries` do probe naquele instante;
   apaga a linha de `probes`; e passa ao ingest os `conn_id` das conexões abertas (o `hide` de hoje, que descarta
   pacotes, eventos e finalização delas). Responde `204`.
2. **Leituras filtram na hora.** Toda leitura de conexões ou consultas (`/probes/{id}`, `/connections?probe=`,
   `/connections`, `/connections/{id}`, `/pcap`, `/raw`, `/dns`, tempo real) exclui as linhas do probe com
   `conn_id ≤ conn_cut` (ou `rowid ≤ dns_cut`) enquanto a linha de `deleted_probes` existir. Tráfego novo com o mesmo
   probe ID depois do `DELETE` tem chave acima do corte e aparece como probe novo (regra da ADR 0034 mantida).
3. **Apagamento em lotes pelo laço de retenção.** As conexões abaixo do corte (com as filhas) e as consultas saem em
   lotes de `DefaultRetentionBatch` (100), cada um numa transação curta, com o passo adaptativo de 25 ms
   (`Retention.adapt`) e a vez do ingest entre lotes; o probe apagado tem prioridade sobre o expurgo por idade.
   Quando nada mais está abaixo do corte, a linha de `deleted_probes` sai. A tabela vive no tmpfs do banco (ADR
   0045): sobrevive ao reinício do store, e o laço retoma.
4. **Meta do teste** (estilo `TestRetentionDoesNotStallIngest`): `DELETE` de um probe com 2500 conexões com um
   ingest simulado gravando; nenhum comando apaga mais que 100 conexões e a maior espera do ingest fica abaixo de
   2 × o maior passo + 20 ms; `TestAPIDeleteProbeOpenConnection` e `TestDeleteProbeAtomic` (ou sucessores) verdes.

## Alternativas consideradas
- **Conjunto de apagados só em memória**: mais simples, mas some no reinício e as conexões ainda não apagadas
  reapareceriam.
- **Lotes sem filtro nas leituras**: durante alguns segundos parte das conexões ainda apareceria; contraria o "na
  hora" da ADR 0034, que é a promessa ao cliente.
- **Teto de conexões por probe**: muda o que o cliente pode medir num probe (carga com um probe só) e não resolve o
  probe grande que já existe.

## Consequências
- Spec 004 (Comportamento do `DELETE`, Dados) atualizada; openapi só na descrição do `deleteProbe` (0.7.0).
- Task 339 (implementer-store), depois da 317 (mesma função), com a migration nova revisada pelo architect.
- Cada leitura de conexões paga um `NOT EXISTS` numa tabela quase sempre vazia (custo desprezível).
