# 0049 — Veredito e sinais v1

Status: aceita (pesos e limiares provisórios — revisar com a carga e o e2e da F8; item 3 e sinais da v1.1: ver 0057; robô sem lista com sinal próprio: ver 0072)
Data: 2026-11-16

## Contexto
Decisão do humano (entrevista, seção 3): sinais do veredito v1 são **incoerências próprias** (UA × JA4/JA4H/Akamai ×
p0f/JA4T × MSS/MTU/`src_kind`), **listas de fingerprints** (base própria medida no espelho, ja4db da FoxIO, listas de
IP de bots publicadas por buscadores e nuvens) e **comportamento** (taxa, rotas, intervalo). O veredito precisa ser
explicável (o site vê por que) e reprodutível (mesma entrada, mesmo resultado na mesma versão das regras e listas).

## Decisão
1. **Saída** (`Verdict`, openapi do bot): `class` ∈ `human`, `good_bot`, `bot`, `suspect`, `unknown`; `score`
   0–100 (quanto maior, mais indício de automação); `signals[]` com `id`, `kind` (`incoherence` | `list` |
   `behavior`), `weight` e `detail`; `view` (`tcp`, `tls`, `http`, `h2`, `h3`, `behavior`: o que havia para
   decidir); `rules_version` e `lists_version`; `subject` (conexão, requisição ou probe avaliado).
2. **Regras como código**: sinais e pesos em Go (`internal/bot/rules`), com `rules_version` = `v1.<n>`, testes de
   tabela com casos golden (curl, Go, Chrome, Firefox, python-requests, navegador headless, Googlebot falso).
   Sem linguagem de regras nem arquivo de configuração de pesos na v1.
3. **Combinação**: `score` = mínimo de 100 e a soma dos pesos dos sinais presentes (pesos negativos para sinais de
   cliente legítimo, piso 0). Classe:
   - `good_bot` quando o IP está numa lista de robô verificado **e** a verificação de DNS reverso/direto passou e o
     UA declara o mesmo robô (prevalece sobre o score);
     (ADR 0057 item 1: para operadores sem sufixo de DNS reverso publicado — OpenAI, DuckDuckGo — a lista basta);
   - senão, `bot` com score ≥ 70, `suspect` com 40–69, `human` com < 40 **e** pelo menos `tls` e `http` na visão;
   - `unknown` com < 40 e visão incompleta.
4. **Sinais v1** (ids estáveis; pesos iniciais na spec 018):
   - incoerência: `ua_tls_mismatch` (família do UA × JA4 da base própria), `ua_h2_mismatch` (UA de navegador × Akamai
     ou ausência de h2), `ua_os_tcp_mismatch` (SO do UA × p0f/JA4T/TTL inicial), `ua_alpn_mismatch`, `ja4h_library`
     (ordem e ausência de campos típicas de biblioteca), `tunnel_mss` (MSS/`mtu_implied` de túnel, peso baixo),
     `ua_missing`, `ua_claims_crawler` (UA de robô conhecido sem verificação);
   - lista: `ja4db_match` (com a aplicação rotulada), `known_client` (base própria; peso negativo para navegador
     coerente), `ip_verified_crawler`, `ip_cloud` (faixas de nuvem/datacenter), `ip_crawler_list_unverified`;
   - comportamento (agregados por IP e site, ADR 0052): `rate_high` (requisições/min acima do limiar),
     `no_reuse` (uma conexão por requisição), `interval_regular` (coeficiente de variação dos intervalos baixo),
     `route_breadth` (muitos caminhos distintos sem recursos estáticos).
5. **Sem dados pessoais nas regras**: as regras leem só o que a spec 018 lista; nenhum sinal usa conteúdo de corpo,
   query string ou valor de cookie.
6. **Mudança de regra** é mudança de comportamento: nova `rules_version`, CHANGELOG, e os goldens das regras
   regravados no mesmo PR.

## Alternativas consideradas
- Modelo de aprendizado de máquina — sem base rotulada; perde a explicabilidade pedida; fica para depois da v1.
- Regras em arquivo (JSON/YAML) recarregável — YAML exige dependência fora da ADR 0009; JSON de pesos sem
  semântica de regra não ganha nada sobre código testado na v1.
- Só listas (ja4db/IP) — falha com clientes que copiam o ClientHello de navegador; as incoerências e o
  comportamento cobrem esses.

## Consequências
- O bot depende das tabelas de família de UA e da base própria (ADR 0050); um UA fora delas tende a `unknown`.
- Pesos e limiares podem mudar depois da carga e do e2e da F8 por uma nova `rules_version`, sem ADR nova enquanto o
  formato do `Verdict` não muda.
