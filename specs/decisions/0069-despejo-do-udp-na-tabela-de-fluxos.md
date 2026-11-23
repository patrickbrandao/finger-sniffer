# 0069 — Despejo do UDP na tabela de fluxos do store

Status: aceita
Data: 2026-11-22

## Contexto
A ADR 0034 item 1 limitou a tabela de fluxos a 8192 entradas e, com ela cheia, despeja "a entrada não estabelecida
mais antiga (TCP sem handshake completo ou UDP não-QUIC sem resposta)"; sem nada a despejar, a 5-tupla nova é
recusada. A justificativa era preservar quem completa o handshake. A task 321 mostrou dois UDP baratos que não são
despejáveis e não completam handshake nenhum: (1) qualquer datagrama com cara de Initial QUIC (primeiro byte
`0xC0`, versão ≠ 0, DCID ≤ 20), para qualquer porta, vira `limited` na hora, mesmo sem resposta e com origem
falsificada; (2) consultas DNS à 53, que o dns sempre responde (TC=1 acima do RRL). 8192 fluxos desses em 30 s
(~273/s) fazem todo SYN legítimo cair em `table_full`; e ~37 falsos Initials/s bastam para todas as conexões novas
saírem degradadas (contam nas simultâneas e gastam fichas das novas/s). Fato novo para a regra.

## Decisão
Altera a ADR 0034 item 1 (definição de "não estabelecida" e ordem de despejo).
1. **UDP só é estabelecido com resposta do espelho.** Um fluxo UDP é despejável (fila `half`, como o TCP
   meio-aberto) até o espelho responder. Para o QUIC, "resposta" é um datagrama do espelho com cabeçalho longo (o
   SCID que `noteQUICCIDs` já guarda) ou um evento h3 da 5-tupla; o formato do primeiro datagrama do cliente não
   basta. Só depois disso o fluxo é `limited`: conta nas simultâneas do modo degradado (ADR 0026) e gasta a ficha das
   novas/s.
2. **UDP não-QUIC respondido** (DNS e afins) tem teto próprio de **2048** entradas (1/4 da tabela): acima dele, o
   fluxo novo desse tipo despeja o mais antigo do mesmo tipo. Com a tabela cheia, a ordem de despejo é: (a) a fila
   `half` (TCP sem o ACK do handshake e UDP sem resposta, inclusive o falso Initial), (b) o UDP não-QUIC respondido
   mais antigo, (c) só então a recusa (`table_full`). As ociosidades não mudam (10 s do TCP meio-aberto, 30 s do UDP).
3. **Métricas**: as de hoje (`fs_store_flows_dropped_total{reason=evicted|table_full}`); o despejo pelo teto do
   item 2 conta em `reason=evicted`.
4. **Sem limite por IP** (ADR 0001) e sem mudança no BPF do capture.

## Alternativas consideradas
- **Tirar a 53/UDP da tabela** (as consultas já vão para `dns_queries` pelo evento): resolve o caso 2, não o 1, e
  perde a análise IP do fluxo DNS.
- **Ociosidade menor para UDP com a tabela acima de 75%**: reduz a janela do ataque, mas não impede a recusa do SYN
  legítimo enquanto durar.
- **Recusar sempre o UDP com a tabela cheia**: deixaria o QUIC legítimo cego durante um SYN flood.

## Consequências
- Spec 004 RF-11a atualizada.
- Task 321 (implementer-store), com os dois cenários em `internal/store/flowcap_test.go`.
- A task 221 (carga contra o teto, bloqueada com o humano) continua dele; quando sair, mede também os dois fluxos
  UDP com o `curl` no meio, com a expectativa de que o `curl` apareça.
- Um QUIC legítimo cujo Initial chega com a tabela cheia pode ser despejado antes de o espelho responder (como o
  SYN hoje); o cliente retransmite o Initial.
