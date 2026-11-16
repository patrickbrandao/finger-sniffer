# 0054 — traefix: o traefik modificado é um projeto externo; respostas às pendências P1–P3, P7 e P8 da F8

Status: aceita
Data: 2026-11-16

## Contexto
A ADR 0048 pôs o fork do traefik em `./traefik/` deste repositório, com o papel `implementer-traefik`, verificação
própria e a imagem `tmsoftbrasil/traefik-finger-sniffer` publicada pelo nosso CI (itens 2 e 7 provisórios, pendências
P1 e P2 da spec 019). Só a preparação da verificação entrou (task 262, PR #238); nada do upstream foi importado.

**Fato novo** — decisão do humano em 2026-11-16, resposta às pendências P1/P2, nas palavras dele: "o traefik será
agora parte de outro projeto, o traefix (x no lugar do k), ele deve permanecer como traefik, me informe quais recursos
preciso adicionar ao fork mantido no projeto traefix (imagem docker hub tmsoftbrasil/traefix:latest) para atender
esse projeto."

Na mesma rodada o humano respondeu: P3 — valem os dois casos de clientes externos, (a) e (b); P7 — manter visível o
tráfego das portas do traefik na API aberta do store, como hoje; P8 — trocar o `traefik-app` do finger-01 pela imagem
do traefix assim que ela atender aos requisitos e passar nos testes, só observando (envia ao bot, sem forwardAuth
bloqueando site nenhum); o bloqueio por site o humano liga depois.

## Decisão
1. **traefix é externo** (substitui os itens 1, 2, 5, 6, 7 e 9 da ADR 0048): o traefik modificado é o projeto
   **traefix**, mantido pelo humano fora deste repositório. Aqui não existem `./traefik/`, o papel
   `implementer-traefik`, o módulo Go do fork, o passo e o job "traefik" da verificação, nem workflow ou segredos do
   Docker Hub. "Permanecer como traefik" é lido como: o traefix é um traefik v3 que aceita a configuração do upstream
   sem mudança (mesmo binário `traefik`, mesmas opções, mesmas portas) e só acrescenta o que a spec 019 pede, desligado
   por padrão.
2. **Spec 019 = requisitos do traefix**: a spec 019 deixa de descrever um fork interno e passa a ser a lista
   autossuficiente do que o traefix tem de oferecer ao finger-sniffer (captura, resumo, ingest, cabeçalhos,
   forwardAuth com fail-open, configuração, métricas, custo, testes de aceite). O conteúdo funcional dos itens 3 e 4 da
   ADR 0048 continua valendo como requisito, agora para o traefix.
3. **Integração por contrato**: a interface entre os projetos é a spec 019, o `cmd/finger-sniffer-bot/openapi.yaml`
   (`TraefikIngestBatch`, `TraefikRecord`, `GET /bot/v1/auth`) e os cabeçalhos `X-Fs-*`. O architect daqui muda esse
   contrato só de forma aditiva em `/bot/v1` (ADR 0001); mudança incompatível vira versão nova da rota e requisito novo
   na spec 019, combinada com o humano. O campo `sender` do lote identifica a versão do traefix.
4. **Imagem**: `tmsoftbrasil/traefix` no Docker Hub, publicada pelo projeto traefix. `latest` serve para experimentar;
   o deploy no finger-01 fixa uma tag imutável por versão (recomendação ao traefix: `<tag-upstream>-traefix.<n>`, ex.:
   `v3.6.2-traefix.1`, que nunca é reescrita) ou, até ela existir, o digest `@sha256:` da `latest` testada. A versão
   aparece em `traefik version` e no `sender`.
5. **Testes**: neste repositório só o lado do bot — contrato do ingest com lotes de exemplo, forwardAuth com os
   `X-Fs-*` simulados, casamento das visões — e, quando o traefix existir no finger-01, o e2e da F8 contra ele (spec 017
   RF-17). Unidade, integração, benchmark e testes do upstream são do projeto traefix e entram como "testes de aceite"
   da spec 019.
6. **P1 sem objeto**: as dependências do traefix são do projeto traefix; a ADR 0009 continua valendo só para o módulo
   do espelho, que segue sem Docker.
7. **P3 — clientes externos, os dois casos**: (a) veredito por probe, com o navegador do visitante abrindo uma conexão
   ao espelho; (b) site externo rodando a imagem pública do traefix com `ingestURL` na 9002 e a própria chave (visão de
   aplicação sem a visão IP/TCP). A ADR 0051 deixa de ser provisória quanto aos clientes externos.
8. **P7 — tráfego dos sites visível**: o store continua expondo na API aberta e no feed global as conexões às portas
   do traefik (ADR 0007 e ADR 0038 item 6 sem mudança). O item 6 da ADR 0052 (`FS_PRIVATE_PORTS`) é descartado.
9. **P8 — troca no finger-01 só observando** (substitui o item 8 da ADR 0048): quando o humano avisar que o traefix
   atende à spec 019 e passou nos testes de aceite dele, uma tarefa de infra (task 273) testa a imagem num container
   à parte, depois troca a imagem do `traefik-app` nos scripts do humano em `tmsoft-servers` (como a ADR 0038 item 6)
   com a configuração estática do `fingerSniffer` ligada: ingest ao bot e `X-Fs-*` aos backends, **nenhum forwardAuth
   nos routers dos sites**; o forwardAuth existe só num router de teste, em modo `observe` e `failOpen`. Volta à
   imagem anterior se qualquer site do humano mudar de resposta. Ligar o forwardAuth ou o modo `block` num site é ação
   do humano.
10. **Licença** (substitui o item 4 da ADR 0053 no que diz respeito ao fork): MIT do upstream e o `NOTICE` das mudanças
    ficam no projeto traefix. O uso não comercial do serviço bot (ADR 0053) não muda.

## Alternativas consideradas
- Manter o fork em `./traefik/` — contrária à decisão do humano.
- `git submodule` do traefix — acopla os CIs e não acrescenta nada à integração por contrato.
- Deploy pela `latest` — não reprodutível: uma publicação nova mudaria o traefik dos sites sem teste.

## Consequências
- Tarefas 263–266 removidas; task 272 desfaz o que a 262 pôs para `traefik/` (mantém o lint do openapi do bot).
- O calendário do traefix é do humano: o e2e da F8 pelo traefix e a troca no finger-01 esperam o aviso dele. Se o
  traefix não estiver pronto na release da F8, o architect escala ao humano (esperar ou lançar só com probe e consulta).
- A spec 019 é o documento que o humano leva ao projeto traefix; mudança nela passa pelo architect e é avisada ao
  humano.
