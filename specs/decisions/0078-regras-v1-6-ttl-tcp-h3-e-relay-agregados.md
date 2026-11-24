# 0078 — Regras v1.6: `ttl_init` TCP × h3 e `relay_rtt_gap` agregados por IP + site

Status: aceita (pesos e limiares provisórios; revisar com as medidas do item 5)
Data: 2026-11-24

## Contexto
A ADR 0065 deixou para uma regra futura (itens 3 e 4, task 314) duas comparações por cliente sobre o cache de
comportamento por IP + site (`internal/bot/agg`): o `ttl_init` das conexões TCP diferente do das conexões h3 do
mesmo cliente (duas pilhas ou caminhos, ex.: proxy que só leva TCP) e o `relay_rtt_gap` agregado, para tirar o ruído
de uma conexão só. Regras atuais: `v1.5` (ADR 0072), com `relay_rtt_gap` por conexão (peso 15, `rtt_gap_us` > 15 ms
e > 30% de `tcp_rtt_us` e `est_to_first_us` > 5 ms; adendo da ADR 0065).

Números da task 313 (adendo da ADR 0065, `docs/dev/traefix-finger-01.md`, seção "fork-point-223"), 90 conexões em
9 grupos de 10, um cliente só (Mac em Wi-Fi, curl e Chrome), relay SOCKS5 por `ssh -D` no próprio host do traefix:
- medianas por grupo, em ms: relay `rtt_gap` 11,9–26,5 e `est_to_first` 9,4–17,5; direto `rtt_gap` 0,8–5,5 e
  `est_to_first` 0,1–1,6;
- por conexão, com `gap` > 10 e `est` > 5 ms: 43 de 50 do relay e 2 de 40 diretas; com os limiares atuais da v1.5,
  35 de 50 e as mesmas 2 de 40 (picos de `tls_rtt` do Wi-Fi com `est_to_first` também alto); as 2 diretas caem em
  grupos diferentes (1 de 10 em cada);
- TTL em h3: `udp.ttl` 56 → `ttl_initial` 64, igual ao TCP do mesmo Mac; o SYN do relay chega com TTL 128 (sysctl do
  host), mas com a origem do próprio host, não a do Mac.

Limites desses números: (1) a mediana por grupo separa relay e direto com folga (5,5 × 11,9 ms no `gap`, 1,6 × 9,4 ms
no `est`), mas é um cliente, uma rede e um relay a 8–10 ms do cliente; (2) **a 313 não mediu o caso do item 1**: no
arranjo dela o TCP pelo relay sai com o IP do host e o h3 com o IP do Mac, então nunca há TCP e h3 do mesmo IP com
`ttl_init` diferente. O caso real é o proxy TCP transparente (ou SOCKS por aplicação) no gateway do cliente, que leva
o TCP com a pilha do gateway enquanto o UDP passa pelo NAT com a pilha do cliente; o Chrome com SOCKS5 configurado
desliga o QUIC e não gera esse caso. Os limiares abaixo são, por isso, provisórios.

Restrição da ADR 0052: não guardar mais dado pessoal que o cache atual; os agregados em disco (`ip_hourly`) são
contagens, e nada novo vai ao banco.

## Decisão
1. **Sinal `ttl_tcp_h3_mismatch`** (tipo `behavior`, peso 10, provisório): na hora corrente do IP + site (o mesmo
   balde de `HourRequests`, que vira na troca da hora), separado pela classe do SO do UA da requisição — `windows`;
   `unix` (`linux`, `macos`, `android`, `ios`); `other` (sem visão HTTP, UA sem SO, bibliotecas) —, o conjunto dos
   `ttl_initial` das conexões TCP e o das conexões h3 são **ambos não vazios e disjuntos** (nenhum valor de h3 visto
   em TCP, e vice-versa). Só entram os valores 32, 64, 128 e 255 (o TTL inicial quantizado da spec 013), da primeira
   requisição de cada conexão (`Reused=false`), com a origem pública (mesmo descarte por origem privada da ADR 0065
   item 4: TTL descartado = não entra). A requisição avaliada lê a classe do seu próprio UA; o sinal dispara em
   qualquer requisição do IP + site daquela classe enquanto a condição valer, TCP ou h3. `detail`:
   `ua os <classe>: initial ttl tcp <lista>, h3 <lista> in the hour`.
   - Por que disjuntos e por classe: todo navegador abre TCP antes de passar a h3 (Alt-Svc), então a pilha de um
     dispositivo aparece nos dois conjuntos; num NAT com vários dispositivos, os conjuntos se cruzam. A separação por
     classe tira o caso comum de PC Windows (128) e telefone (64) no mesmo NAT, em que um deles vai direto a h3 pelo
     Alt-Svc guardado de outra hora. Dentro de uma classe, os dispositivos têm o mesmo `ttl_init`; conjuntos
     disjuntos ali pedem outra pilha no caminho.
   - Peso baixo: sinal de caminho, não de bot (como o relay); com UA Windows atrás de proxy Linux ele soma com
     `ua_os_tcp_mismatch` das conexões TCP, e dá a marca também às conexões h3 do mesmo cliente.
2. **Sinal `relay_rtt_gap_agg`** (tipo `behavior`, peso 10, provisório): nas conexões TCP com tempos do traefix do IP
   + site na hora corrente (primeira requisição de cada conexão, com `tcp_rtt_us`, `est_to_first_us` e `rtt_gap_us`
   conhecidos ou `tls_rtt_us` para calculá-lo, como na v1.5), com **n ≥ 5** conexões: a mediana do `rtt_gap_us` >
   **10 ms**, a mediana de `rtt_gap_us`/`tcp_rtt_us` > **0,3** e a mediana do `est_to_first_us` > **5 ms**. A mediana
   passa do limiar quando mais da metade das conexões passa; o cache guarda só as contagens (`timed`, `gap`, `frac`,
   `first`) e dispara com `2·gap > timed`, `2·frac > timed` e `2·first > timed`, sem nenhuma amostra.
   `detail`: `<timed> tcp connections in the hour: rtt gap > 10 ms in <gap>, > 30% of tcp rtt in <frac>, first byte
   > 5 ms in <first>`.
   - Os limiares da conexão única (v1.5) ficam como estão; o agregado usa `gap` > 10 ms porque a mediana já tira os
     picos do Wi-Fi que a conexão única não tira (pelos números da 313, todos os grupos do relay passam e nenhum
     direto chega perto). `relay_rtt_gap` (15) e `relay_rtt_gap_agg` (10) somam 25 no máximo: relay sozinho continua
     abaixo de `suspect` (40), como manda a ADR 0065 item 3 ("relay não é bot"); o valor do agregado é marcar de forma
     estável todas as requisições do cliente (inclusive h3 e as conexões que a regra da conexão perdeu).
   - Só TCP: h3 não tem `rtt_gap` (ADR 0065 item 2).
   - Sem os tempos (perfil `basic`, PT-17), o sinal nunca dispara.
3. **Dados e minimização (ADR 0052)**: os novos campos ficam só no acumulador da hora corrente em memória do
   comportamento IP + site que já existe (mesma chave, mesmos tetos da ADR 0073 item 7, nenhuma entrada nova); não
   entram em `counters`/`ip_hourly`, não vão ao banco (sem migration), não passam para as horas fechadas do cache e
   somem na troca da hora; o `forget` os apaga com a entrada. Por entrada: três pares de máscaras de 4 bits (TCP e h3
   por classe de SO, 3 bytes) e quatro contadores saturados em 65 535. Nenhum tempo, TTL cru, UA ou família é
   guardado; a classe de SO só escolhe a máscara. É dado derivado do que o índice de conexões já tem por 10 min, com
   vida de até 1 h e sem identificador novo; a tabela da ADR 0052 item 1 não muda.
4. **Versão e contrato**: rules `v1.6`. `Signal.id` do openapi do bot é texto livre que remete à tabela da spec 018:
   o openapi não muda (continua 0.8.0). Nos goldens atuais muda só o `rules_version` (campos novos de `Behavior`
   omitidos do JSON quando vazios; nenhuma classe, pontuação ou sinal muda); entram goldens novos para os dois sinais (disparo, limiar, n < 5, conjuntos que se cruzam,
   classes de SO diferentes, valor de TTL fora de 32/64/128/255).
5. **Revisão** (gatilho desta ADR, além do da ADR 0049): (a) medir o item 1 com um cliente atrás de proxy TCP
   transparente no próprio gateway (TCP e h3 com o mesmo IP de saída) e com um NAT de ≥ 2 dispositivos de SO
   diferentes; (b) medir o item 2 com relay longe do cliente (≥ 30 ms), com cliente em rede móvel e com outro relay
   que não esteja no host do traefix; (c) qualquer falso positivo de `relay_rtt_gap_agg` num cliente direto real.
   Até lá, pesos 10 e os limiares acima.

## Alternativas consideradas
- Guardar amostras (últimos N tempos ou TTL por conexão) para a mediana exata — mais dado pessoal em memória sem
  ganho: a mediana contra um limiar fixo só precisa das contagens.
- Histograma dos tempos por faixa — permitiria mudar o limiar sem reprocessar, mas guarda a distribuição dos tempos
  do cliente; descartado pela ADR 0052.
- `ttl_init` diferente sem separar por SO — o NAT doméstico com Windows e telefone dava falso positivo assim que um
  dos dois fosse direto a h3.
- Conjuntos de TTL sem exigir disjunção (basta haver dois valores) — falso positivo em todo NAT com dois sistemas.
- Peso 15 no agregado, igual ao da conexão — relay sozinho chegaria a 30, e com `no_reuse` (10) a `suspect` para um
  humano atrás de VPN corporativa.
- Janela deslizante de 60 min — o cache já trabalha por hora de relógio (`no_reuse`, `route_breadth`); outra janela
  exigiria guardar instantes.
- Gravar os contadores novos em `ip_hourly` — migration e dado novo em disco por 7 dias sem uso: as regras só leem a
  hora corrente.

## Consequências
- Spec 018: RF-05 com `v1.6`, RF-09 com os campos só da hora corrente, tabela de pesos com os dois sinais.
- Task 314 (implementer-bot): `internal/bot/agg` (campos da hora corrente e `Stats`), `internal/bot/rules` (sinais,
  `Behavior`, `RulesVersion`, auxiliares de classe de SO e de forma do relay), `internal/bot/judge.go` (preencher
  `agg.Request` e `rules.Behavior`), goldens e `docs/bot.md`.
- ADR 0065 itens 3 e 4: a "regra futura" passa a ser esta.
- `docs/bot.md`: as duas linhas da tabela de sinais entram junto com esta ADR (bloco exato da task 314, ADR 0023;
  o `TestBotDoc` exige toda linha da tabela da spec 018), marcadas como "entra em produção com a task 314".
