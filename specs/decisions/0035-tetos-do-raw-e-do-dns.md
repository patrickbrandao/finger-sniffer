# 0035 — Tetos do raw e do RRL do dns (auditoria de 2026-11, agrupados)

Status: aceita
Data: 2026-11-14

## Contexto
A auditoria de 2026-11-10 achou no raw e no dns limites ausentes ou que não batem com a spec:
- **156**: o raw não tem teto global de sessões simultâneas; cada sessão ociosa vive até `FS_IDLE_DEFAULT`
  (spec 006 RF-07), e o processo tem `MemoryMax=96M`.
- **162**: `n=` do modo `source` não tem máximo; um `PROBE x mode=source n=999999999999` faz o raw gerar bytes e o
  store guardá-los até os tetos de fluxo.
- **147**: o RRL do dns usa o mesmo balde por IP para UDP e TCP e descarta respostas TCP, o que não protege contra
  amplificação (TCP não amplifica) e quebra o fallback TC=1 → TCP do próprio cliente.
- **163**: em IPv6 o balde é por /128 (um atacante tem 2^64 endereços num /64) e, com a tabela de baldes cheia, o
  RRL deixa passar tudo (fail-open).
- **184**: `FS_MAX_CONNS=0` tem significado só no store (ADR 0034, item 12).

## Decisão
1. **Teto global de sessões do raw (156).** No máximo `FS_MAX_CONNS` sessões simultâneas somando todos os
   listeners do raw (mesma variável do web e do store; ≤ 0 → padrão 250 com aviso, regra da ADR 0034 item 12). Sem
   vaga, o raw **não aceita**: o accept espera (o excedente fica no backlog do kernel), e nenhuma sessão aceita é
   fechada antes de `FS_IDLE_DEFAULT` (spec 006 RF-07 mantida). O accept bloqueado sai no desligamento.
2. **Máximo de `n=` (162).** `n` acima de **64 MiB** (= `FS_SIZE_MAX` do web) é cortado para 64 MiB; a linha
   `PROBE` continua válida. Sem campo novo no contrato (`source_clamped` fica fora); o tamanho real enviado aparece
   em `writes_out` e no fluxo `out`.
3. **RRL só em UDP (147).** O limite `FS_DNS_RRL_PER_IP` vale para respostas UDP (acima: TC=1). O TCP fica fora do
   RRL e tem limites próprios do servidor (conexões simultâneas, consultas por conexão e ociosidade). `rate_limited`
   só aparece em consultas UDP.
4. **Chave e transbordo do RRL (163).** O balde é por IP de origem em IPv4 e **por /64** em IPv6. Com a tabela de
   baldes cheia, as origens sem balde próprio dividem **um balde de transbordo** com a mesma taxa; não há fail-open.
5. **Eventos grandes do raw (149).** Com o corte das listas do ClientHello (ADR 0032, item 5) o evento cabe; se
   ainda passar de 900 KiB, o raw o descarta com log e `raw_events_oversize_total`, e o produtor comum trata
   `nats.ErrMaxPayload` como erro definitivo (descarta e conta em `dropped_events_total`, sem travar a fila).

## Alternativas consideradas
- Variável própria para o raw (`FS_RAW_MAX_CONNS`): o limite é o mesmo conceito de capacidade do RNF-01; uma chave
  a mais sem caso de uso.
- Fechar a sessão excedente logo depois do accept: o cliente veria um fechamento do espelho que não pediu,
  contrariando a spec 006 RF-07; esperar no backlog só atrasa o handshake.
- Recusar a linha `PROBE` com `n` acima do máximo: o cliente perderia o teste inteiro por um parâmetro; o corte
  segue a regra de `clamped` dos controles do web.
- Balde próprio para TCP no RRL: mais estado para um protocolo que não amplifica.
- RRL por /56 em IPv6: agrega mais clientes legítimos de um mesmo provedor; /64 é a menor sub-rede atribuída a um
  enlace.
- Fail-open documentado com a tabela cheia: um atacante que enche a tabela desliga o RRL para todos.

## Consequências
- Specs 006 (RF-01, RF-02, RF-04, RF-07a nova, métricas) e 007 (RF-04) atualizadas; descrição de `rate_limited`
  no openapi 0.6.0 (ADR 0032).
- Tarefas: 156 e 162 (raw), 149 (raw e `pkg/service`), 147 e 163 (dns).
