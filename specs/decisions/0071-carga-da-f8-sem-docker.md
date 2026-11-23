# 0071 — Gerador da carga da F8 como unit transitória, sem Docker

Status: aceita
Data: 2026-11-22

## Contexto
`test/load/f8-remote.sh` (carga da F8, tasks 285 e 309) importa uma imagem no Docker do finger-01 e sobe
containers `fs-load-f8-*` na rede `network_public` do `traefik-app`, para o `botload` falar com a 9003 do bot com
origem dentro de `10.249.0.0/16`. A ADR 0038 item 9 deixa o Docker e os containers do host fora do espelho, a spec
016 põe "Docker para o espelho" fora de escopo e a única exceção escrita é o container de teste do traefix (spec 016
RF-15). Não há registro de aprovação do humano (task 396). Fato que permite outro caminho: a 9003 aceita loopback e
`10.249.0.0/16`, e um processo no host que conecta a `10.249.255.254:9003` (endereço da bridge no próprio host) sai
com essa origem, sem tocar o Docker.

## Decisão
1. O gerador do bot da carga da F8 roda como **unit transitória do systemd** do espelho:
   `systemd-run --unit=finger-sniffer-load-f8-<nome> --collect -p CPUQuota=100% -p MemoryMax=1G
   -p MemorySwapMax=0`, binário em `/finger-sniffer/tmp/`, alvo `http://10.249.255.254:9003` (ou loopback quando a
   origem não importar). É uma unit `finger-sniffer-*`, dentro do que a ADR 0038 item 9 já permite sem aprovação.
2. A unit fica **fora** de `finger-sniffer.slice` (no `system.slice` padrão do `systemd-run`), para o gerador não
   disputar a cota de 800% e os 6G do espelho que a carga mede. O script para a unit e apaga o binário no fim,
   inclusive por sinal (`trap`).
3. Nenhum gerador de carga ou e2e usa o Docker do host. A exceção do container de teste do traefix (spec 016 RF-15)
   continua a única.

## Alternativas consideradas
- **Registrar a exceção do Docker**: exigiria a confirmação do humano (specs/002, escalonamento item 4) para algo
  que o caminho sem Docker resolve com a mesma origem e os mesmos limites.
- **Gerador dentro de `finger-sniffer.slice`**: misturaria a CPU do gerador com a do espelho na medida.
- **Gerador no Mac**: a origem pública passaria pelo caminho da internet e a 9003 não a aceita sem chave.

## Consequências
- Spec 017 (RF-17, carga da F8) atualizada; task 396 (tester) troca o `f8-remote.sh` e a seção do
  `test/load/RESULTS.md`, e nenhuma linha de `test/load/` chama o Docker.
- A medida passa a sair do namespace de rede do host, não de um container: o tester confere na primeira execução
  que a origem vista pelo bot é `10.249.255.254` e registra no `RESULTS.md`.
