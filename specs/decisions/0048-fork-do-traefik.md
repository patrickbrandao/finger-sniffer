# 0048 — Fork do traefik em `./traefik/`, papel `implementer-traefik` e imagem no Docker Hub

Status: substituída por 0054 (itens 1, 2, 5–9: o fork é o projeto externo traefix; itens 3 e 4 seguem como requisitos na spec 019)
Data: 2026-11-16

## Contexto
Decisão do humano (entrevista de 2026-11-15, seção 3): a pasta `./traefik/` deste repositório contém o projeto do
traefik, mantido por um agente próprio, que captura os dados necessários (ClientHello, h2/h3, porta de origem…) e
acrescenta cabeçalhos com IP e porta de origem (e id de correlação) para o serviço interno consultar a API. A imagem
vai para o Docker Hub como `tmsoftbrasil/...`, com credencial configurada pelo humano.

O traefik é Go (licença MIT), com centenas de dependências próprias no `go.mod`, e roda no finger-01 como o
container `traefik-app` do humano (`traefik:latest`). A ADR 0009 fixa a lista de dependências do espelho e "sem
Docker".

## Decisão
1. **Código**: o upstream `traefik/traefik` numa tag estável v3 fixada (a mais recente na tarefa de importação)
   entra em `./traefik/` por `git subtree add --squash` (histórico do upstream fora do nosso). Os patches são
   commits nossos por cima; `traefik/FORK.md` registra a tag base, a lista de patches e como atualizar
   (`git subtree pull --squash` para a tag nova, uma por vez, com o CI do fork verde). O código nosso dentro do fork
   fica num pacote próprio, `traefik/pkg/fingersniffer/`, e os ganchos no código do upstream são o mínimo possível
   (wrapper do listener/conexão, middleware, opção do forwardAuth), para o rebase ser barato.
2. **Dependências (provisória, pendência P1 da spec 019)**: `traefik/` é um **módulo Go separado** (`traefik/go.mod`
   do upstream), fora do módulo do espelho e fora da lista da ADR 0009: as dependências do upstream vêm com a
   decisão do humano de fazer o fork. Qualquer dependência **nova além das do upstream** no fork segue a regra da ADR
   0009 (escala ao humano). O fork não importa o módulo do espelho: o que precisa (enquadramento do TLS e do h2) é
   só cópia de bytes; o cálculo das fingerprints fica no bot (ADR 0047 item 3).
3. **O que o fork faz** (spec 019):
   - por conexão TLS da entrada: copia os bytes do ClientHello cru (até 16 KiB), SNI, ALPN negociado, versão;
     no h2, os primeiros bytes do cliente depois do prefácio até o fim do primeiro `HEADERS` (até 16 KiB); id da
     conexão (ULID) e origem/destino como o socket os vê;
   - por requisição: método, authority, caminho sem query, nomes dos campos na ordem, valores só de uma lista
     permitida (`User-Agent`, `Accept`, `Accept-Language`, `Accept-Encoding`, `Sec-CH-UA*`, `Sec-Fetch-*`), nomes
     dos cookies e o JA4H calculado com os valores (nunca os valores de `Cookie`/`Authorization`), status e tempos;
   - envia isso ao bot em lote (`POST /bot/v1/ingest/traefik`), assíncrono, com fila limitada e descarte contado:
     nunca atrasa a requisição;
   - acrescenta à requisição encaminhada ao backend `X-Fs-Src-Ip`, `X-Fs-Src-Port`, `X-Fs-Dst-Port`,
     `X-Fs-Conn-Id` e `X-Fs-Proto`, e **remove** qualquer `X-Fs-*` que venha do cliente;
   - forwardAuth com **fail-open** opcional (`failOpen`, prazo `timeout`): sem resposta do servidor de auth no
     prazo, a requisição segue com `X-Fs-Verdict: unavailable` em vez do 500 do upstream.
4. **Configuração**: opções estáticas do traefik (`experimental.fingerSniffer`: URL do ingest, chave opcional,
   tamanho da fila, entradas cobertas) e a opção `failOpen`/`timeout` no middleware `forwardAuth`; tudo desligado
   por padrão (o fork sem configuração se comporta como o upstream).
5. **Papel `implementer-traefik`** (specs/002, `.claude/agents/implementer-traefik.md`): dono de `traefik/**`.
   Mudança no enquadramento enviado ao bot é contrato (openapi do bot, architect).
6. **Verificação**: `traefik/**` fica fora do `verify-quick`/`verify-full` do módulo raiz (lint, vet, testes,
   cobertura, govulncheck); um passo próprio roda `go build ./cmd/traefik` e os testes de
   `traefik/pkg/fingersniffer/...` e dos pacotes tocados pelos ganchos, quando `traefik/**` muda (quick) e sempre
   (full e CI). Os testes completos do upstream não rodam no nosso CI.
7. **Imagem (provisória, pendência P2)**: `tmsoftbrasil/traefik-finger-sniffer` no Docker Hub, `linux/amd64`, tags
   `<tag-upstream>-fs.<n>` (ex.: `v3.6.2-fs.1`) e `sha-<commit curto>`, sem `latest`; construída a partir de
   `traefik/Dockerfile.fs` (build do binário estático do fork e o `webui` como o upstream entrega) e publicada pelo
   workflow `traefik-image` na tag git `traefik-v<tag-upstream>-fs.<n>`, com os segredos `DOCKERHUB_USERNAME` e
   `DOCKERHUB_TOKEN` do repositório criados pelo humano (specs/002 item 4: configuração do GitHub). A senha nunca vai
   para arquivo nem para o agente.
8. **Troca no finger-01**: o `traefik-app` passa a usar a imagem do fork e os sites ligam o forwardAuth só com o aval
   do humano, numa tarefa de infra que edita os scripts do humano em `tmsoft-servers` (como na ADR 0038 item 6),
   primeiro com um site de teste.
9. **Licença**: o fork mantém o `LICENSE.md` (MIT) do upstream e acrescenta um `NOTICE` com as mudanças; a imagem
   leva os rótulos OCI de origem e licença.

## Alternativas consideradas
- Plugin do traefik (Yaegi) — plugins de middleware não veem o ClientHello nem os bytes do h2, e o interpretador
  limita desempenho.
- Repositório separado para o fork — exige criar repositório no GitHub (humano) e quebra a decisão de manter em
  `./traefik/`.
- `git submodule` — o fork continuaria num repositório próprio.
- Fork calculando as fingerprints — duplicaria `pkg/fingerprint` num módulo separado, com o risco de as duas cópias
  divergirem.
- forwardAuth carregando o ClientHello em cabeçalhos — a consulta pelo site também precisa desses dados, e
  cabeçalhos de alguns KiB por requisição pesam mais que um envio por conexão.

## Consequências
- O repositório cresce com o código do upstream (sem o histórico dele); `.gitignore`, lint e CI tratam `traefik/`
  à parte.
- Atualizar o traefik é tarefa explícita do `implementer-traefik`, com o CI do fork e uma imagem nova.
- A ADR 0009 continua valendo para o espelho; "sem Docker" vale para o espelho, não para o fork.
