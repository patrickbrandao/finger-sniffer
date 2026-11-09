# 0021 — Cabeçalho Date nas respostas HTTP de todas as versões

Status: aceita
Data: 2026-11-09

## Contexto
O e2e da F4 (task 060) mostrou respostas h3 sem `Date`. Conferido na vps602: o h2 manda `date` (o `x/net/http2`
acrescenta sozinho), mas o HTTP/1 também não manda, porque o escritor é próprio (spec 009) e só escreve o que a rota
e os controles pedem. Nenhuma spec tratava do `Date`. A RFC 9110 §6.6.1 exige que um servidor de origem com relógio
gere `Date` nas respostas 2xx, 3xx e 4xx, e manda o intermediário que encaminha uma resposta sem `Date` acrescentar
o seu. Para o consumidor principal (o teste de não-interferência do go-xproxy) isso importa nos dois sentidos: uma
resposta sem `Date` faz o proxy conforme acrescentar o cabeçalho, o que vira diferença entre caminhos que não vem do
cliente; e testar se o proxy acrescenta `Date` é um caso útil, que precisa de um jeito de omiti-lo.

## Decisão
- O web manda `Date` (IMF-fixdate, UTC, hora em que o cabeçalho é escrito) em **toda resposta final** de HTTP/1.x,
  h2 e h3, inclusive 5xx e as respostas de erro do próprio espelho (400 de controle inválido, 431, 426). As
  respostas 1xx não levam `Date`.
- Posição: no HTTP/1, `Date` é o primeiro campo depois da linha de status; no h2 e no h3, o primeiro campo regular
  depois de `:status`. Os campos de `h=` vêm depois, na ordem pedida.
- `h=Date:<valor>` substitui o valor automático (vale o literal, na caixa pedida, na posição de `h=`).
- Controle novo `date=0`: omite `Date` (para observar se o caminho acrescenta). Qualquer outro valor é inválido (400).
- O `Date` enviado aparece nos bytes registrados (`response_sent`, fluxo `out`) como qualquer outro campo; o
  contrato não muda (`controls.params` já é um mapa livre).

## Alternativas consideradas
- Não exigir `Date` em nenhuma versão: o espelho seria não conforme, e o h2 continuaria mandando pelo `x/net` (seria
  preciso suprimir), deixando o comportamento diferente do que os clientes reais encontram em servidores comuns.
- Exigir só no h3 "como no h1/h2": partia de uma premissa errada (o h1 também não manda).

## Consequências
- Tarefa do implementer-web na F5 (h1 e h3 passam a mandar; `date=0` nas três versões; testes byte a byte dos
  controles atualizados). Os golden de respostas do web mudam.
- `docs/probes.md` documenta `date=0`.
