# 0031 — MSS/MTU derivados do SYN e tipo do endereço de origem

Status: aceita
Data: 2026-11-14

## Contexto
A análise do projeto externo tcp-analyzer (`tmp/relatorio-tcp-analyzer-01.md`, seções 2.2, 6 e 7; tasks 193 e
194) mostrou duas leituras de "como a conexão chegou" que o espelho tem o dado para fazer melhor que ele, mas não
publica:
- **MSS e MTU implícito.** O tcp-analyzer infere o MTU do caminho pelo socket (`tcpi_snd_mss`, `tcpi_advmss`,
  `IP_MTU`) e erra, porque esses valores refletem a interface do servidor. O espelho captura o SYN e tem o MSS que
  chegou (o anunciado pelo cliente, já reescrito por qualquer clamping no caminho), mas só o publica cru em
  `tcp.syn.options` (`["mss",N]`). Para comparar caminhos, o cliente refaz a conta.
- **Tipo da origem.** Uma origem Teredo (`2001::/32`) ou 6to4 (`2002::/16`) revela um túnel de transição do lado
  do cliente que nenhum outro campo mostra. O tcp-analyzer classifica o IPv6 do cliente, mas confere NAT64 como
  /32 e descreve o cenário errado (6.7 do relatório): `64:ff9b::/96` só aparece como origem se um tradutor
  (SIIT/NAT46) na frente do servidor converteu um cliente IPv4; um cliente IPv6-only com NAT64/464XLAT chega por
  IPv6 nativo ou pelo IPv4 do NAT64.

Fatos que orientam a decisão:
- A ADR 0028 deixa a interpretação ao cliente. A spec 013 já publica valores **derivados por regra fixa**
  (`ip.ttl_initial`, `ip.hops`) e um palpite (`tcp.os_guess`), mas o palpite vem de um banco externo versionado
  (`p0f.fp`, `FS_P0F_DB`), não de uma tabela própria do espelho.
- Pelo SYN não se separa MTU reduzido de MSS clamping (CPE, BRAS, firewall), e as faixas de VPN se sobrepõem
  (WireGuard, OpenVPN, IPsec ESP com e sem NAT-T, redes móveis com clamping em 1380–1400). Uma tabela de "causa
  provável" no contrato ficaria presa à regra de compatibilidade aditiva (ADR 0001) e mudar uma faixa seria mudar
  comportamento acordado.
- O MSS que o **cliente** anuncia limita os segmentos que o **espelho** envia, não os que o cliente envia. Os
  segmentos do cliente (`tcp.segments_in`) são limitados pelo MSS do SYN-ACK do espelho. A proposta 3 da task 193
  ("segmento de dados maior que `syn_mss` indica reescrita") está invertida.
- A classificação do endereço é por prefixos fixos da IANA (registros de uso especial), sem interpretação.

## Decisão
Mudança **aditiva** no openapi: **0.5.0** (nada removido nem renomeado). O asyncapi não muda (os campos são
calculados pelo store, nenhum payload de evento muda) e fica em 0.4.1. Registros gravados antes do 0.5.0 não têm
os campos novos (ausentes, não nulos), como no 0.4.0.

1. **MSS e MTU no `TCPInfo` (spec 013 RF-06a), calculados pelo store só a partir do primeiro SYN do cliente**
   (retransmissão não substitui, como `ip.packets.syn`):
   - `syn_mss` (`integer | null`): valor da **primeira** opção MSS do SYN; nulo sem a opção ou sem SYN (UDP,
     conexão vista sem o SYN).
   - `mtu_implied` (`integer | null`): `syn_mss + 40` (IPv4) ou `syn_mss + 60` (IPv6), os cabeçalhos fixos de IP
     e TCP (RFC 9293 §3.7.1). **Não** soma os 12 bytes de timestamps: o MSS do SYN não os desconta (quem soma é
     quem parte do `snd_mss` do socket). Nulo quando `syn_mss` é nulo.
   - `mss_reduction` (`integer | null`): `1460 − syn_mss` (IPv4) ou `1440 − syn_mss` (IPv6), referência = MTU
     Ethernet 1500. Negativo quando o MTU implícito passa de 1500 (jumbo). Nulo quando `syn_mss` é nulo.
   - O valor é o que **chegou** ao espelho: inclui qualquer reescrita do caminho. A descrição no contrato diz que
     MTU reduzido e MSS clamping dão o mesmo número.
2. **`mss_hint` não entra no contrato.** A tabela de causas prováveis fica como receita em `docs/probes.md`
   (task 195 e a tarefa de docs desta ADR), com a ressalva do clamping. Tabela de referência para a doc
   (redução em relação a 1460/1440; valores típicos, não uma função):

   | Redução | MTU implícito | Causas prováveis (ou clamping no mesmo valor) |
   | --- | --- | --- |
   | < 0 | > 1500 | jumbo frames (caminho local ou de datacenter) |
   | 0 | 1500 | Ethernet sem encapsulamento visível |
   | 8 | 1492 | PPPoE |
   | 20 | 1480 | túnel com cabeçalho IPv4 externo (6in4, 6rd, IPIP) |
   | 24–28 | 1476–1472 | GRE (sem e com chave) |
   | 40–100 | 1460–1400 | VPN (WireGuard com MTU 1420 = 80, OpenVPN, IPsec ESP 50–90 conforme cifra e NAT-T), rede móvel |
   | > 100 | < 1400 | encapsulamentos múltiplos ou clamping agressivo |
   | 220 (só IPv6) | 1280 | MTU mínimo do IPv6 (Teredo e túneis que fixam 1280) |
3. **Sem campo auxiliar de "MSS máximo visto".** `tcp.segments_in` (RF-09) já traz o tamanho dos primeiros
   segmentos; a doc explica a leitura certa: só com o cliente mandando mais de um segmento cheio, um
   `max(segments_in)` menor que o MSS do SYN-ACK do espelho (1460/1440, menos 12 com timestamps) indica MSS do
   SYN-ACK reescrito no caminho ou PMTUD do cliente; maior indica reescrita para cima ou violação. Os pedidos
   típicos das sondagens são pequenos, então o sinal raramente existe e não justifica campo.
4. **`ip.src_kind` no `IPInfo` (spec 013 RF-05a)**, calculado pelo store do endereço de origem da conexão (o do
   cliente), em TCP e UDP. Enum final, avaliado nesta ordem (primeira regra que casa):

   | Valor | IPv4 | IPv6 |
   | --- | --- | --- |
   | `loopback` | `127.0.0.0/8` | `::1/128` |
   | `link_local` | `169.254.0.0/16` | `fe80::/10` |
   | `private` | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918) | `fc00::/7` (ULA, RFC 4193) |
   | `shared` | `100.64.0.0/10` (CGNAT, RFC 6598) | — |
   | `teredo` | — | `2001::/32` (RFC 4380) |
   | `6to4` | — | `2002::/16` (RFC 3056, obsoleto pela RFC 7526) |
   | `nat64` | — | `64:ff9b::/96` (RFC 6052) e `64:ff9b:1::/48` (RFC 8215) |
   | `other` | não unicast (`0.0.0.0/8`, multicast `224.0.0.0/4`, `240.0.0.0/4` com o broadcast) e uso especial: `192.0.0.0/24`, documentação (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), benchmarking (`198.18.0.0/15`) | não unicast (`::/128`, multicast `ff00::/8`), IPv4 mapeado `::ffff:0:0/96`, descarte `100::/64`, documentação (`2001:db8::/32`, `3fff::/20`), benchmarking (`2001:2::/48`) |
   | `global` | todo o resto | todo o resto |

   - Não há valor `ipv4`: a família já está em `family`.
   - `nat64` fica com um só valor para os dois prefixos e a descrição diz que **só** aparece com um tradutor
     SIIT/NAT46 na frente do servidor (cliente IPv4 traduzido); não indica NAT64 do lado do cliente. A vps602
     não tem tradutor, então na prática não aparece no espelho; existe para não classificar o prefixo como
     `global`.
   - `shared` fica: um endereço CGNAT que chega a um servidor público denuncia um caminho interno à operadora, e
     sem o valor ele cairia em `global`.
   - Fica em `ip` (o resumo da conexão na listagem não muda).
   - Fora: decodificar o IPv4 embutido em Teredo/6to4 (o cliente faz pelos prefixos documentados).

## Alternativas consideradas
- `mss_hint` no contrato, como o `os_guess`: o `os_guess` é a saída de um banco externo versionado; o `mss_hint`
  seria uma tabela própria com faixas sobrepostas e sem como separar clamping, congelada pela compatibilidade
  aditiva. Interpretação é do cliente (ADR 0028); a doc dá a tabela sem prendê-la ao contrato.
- Objeto `tcp.mss {value, mtu_implied, reduction}`: os campos do `TCPInfo` são planos e nuláveis
  (`rtt_handshake_ms`, `ts_clock_hz`); um objeto a mais só acrescenta um nível de nulo.
- Só documentar a conta (sem campos): a conta depende da família e do primeiro SYN; publicá-la evita que cada
  cliente erre os 12 bytes de timestamps, como o tcp-analyzer, e é derivação fixa como `ttl_initial`.
- `max_seg_in` ou um booleano de "MSS reescrito": a comparação proposta estava invertida e a certa depende de
  tráfego de upload que as sondagens quase não têm.
- Enum do `src_kind` com `ipv4` genérico e `ula` separado de `private`: duplica `family`; `private` cobre RFC 1918
  e ULA com a mesma leitura (rede privada atrás de NAT ou teste local).
- Separar `nat64_wkp` de `nat64_local`: nenhum caso real no espelho distingue os dois.

## Consequências
- Spec 013: RF-05a (`ip.src_kind`) e RF-06a (`syn_mss`, `mtu_implied`, `mss_reduction`), com critérios de aceite.
- openapi 0.5.0; spec 004 cita a versão. asyncapi sem mudança.
- Tarefas: implementer-store (cálculo em `internal/store/analysis.go`, exemplos golden do openapi regravados),
  tester (golden de SYN com MSS 1460, 1452, 1440, 1380, sem MSS, IPv6 1440/1432 e 1220, e a tabela de endereços,
  um por valor do enum) e docs (`docs/api.md` 0.5.x e a receita de `docs/probes.md` lendo os campos novos, depois
  da task 195).
- Muda o registro em runtime do store (campos novos): implantado com a entrega do store.
