# 0027 — Janela de 200 ms do excesso de conexões simultâneas no modo degradado

Status: aceita
Data: 2026-11-09
Altera: 0026 (item 4, tolerância de rajada ≤ 100 ms).

## Contexto
A ADR 0026 (item 4) admitiu, sem nova ADR, uma tolerância de até 100 ms à reordenação de uma rajada antes de o
limite de 200 simultâneas (spec 004 RF-11) degradar, e exigiu nova ADR para uma janela maior. Fato novo da
task 108 (#106), visto na carga oficial: depois de uma pausa de ~360 ms no caminho, 18 SYNs novos chegam em 5 ms
e os FINs das 20 conexões que terminaram na pausa chegam de +3 a +70 ms **no próprio tempo de captura**. Aplicar
antes os fechamentos do mesmo lote não basta (os FINs não estão no lote), e uma janela de 100 ms cobre os 70 ms
observados sem folga.

## Decisão
- O limite de `FS_MAX_CONNS` simultâneas só degrada quando o excesso (vivas ≥ limite, contadas como na ADR 0026)
  **dura mais de 200 ms no tempo de captura**. A janela abre na primeira conexão criada que vê a conta no limite e
  fecha na primeira que a vê abaixo; conexões criadas dentro da janela não saem `degraded` por esse limite.
- Dentro da janela o excesso continua limitado pelo balde de `FS_MAX_NEW_CONNS_PER_S` (no máximo ~60 conexões a
  mais com os valores padrão); o limite de novas/s não tem janela.
- `FS_MAX_CONNS=0` continua degradando tudo, sem janela.
- A janela é fixa (200 ms), não configurável.

## Alternativas consideradas
- Reordenar os fechamentos do lote antes de decidir (ADR 0026): não resolve, os FINs chegam depois dos SYNs.
- Janela de 100 ms: no limite do observado (70 ms), sem folga para outra pausa maior.
- Janela configurável por variável de ambiente: mais uma chave sem caso de uso; revisar se a medição pedir.
- Janela de 1 s ou mais: deixaria um excesso sustentado de até ~50 conexões por segundo antes de proteger o
  armazenamento.

## Consequências
- Spec 004 RF-11 passa a dizer "acima de 200 por mais de 200 ms"; ADR 0026 aponta para esta no item 4.
- Implementação já entregue na task 108 (`internal/store/flows.go`, testes `TestOverloadedBurstAfterPause` e
  `TestOverloadedSustainedExcess`).
