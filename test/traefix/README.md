# traefix de teste no finger-01

Ambiente reproduzível da conferência do `tmsoftbrasil/traefix:latest` (task 406; antes montado à mão nas tasks 273 e
313). Serve para conferir cada pedido `PT-nn` entregue e para detectar regressão da spec 019 RF-14 quando a `latest`
muda (ADR 0062 itens 7 e 8): um comando sobe o mesmo ambiente, o e2e `TestF8TraefixReal` roda contra ele e os lotes
reais ficam gravados.

| Arquivo | O que é |
| --- | --- |
| `static.yml` | configuração estática: entradas `fstest` (perfil da spec 019 RF-03, TCP e UDP `:18443`), `fsnoraw` (`:18446`, `rawBytes: false`), `fsh3o` (TCP e UDP `:18447`, `http3HeaderOrder: true`), `fsplain` (`:18444`, sem `fingerprint`), `fsmetrics` (`127.0.0.1:18082`, `/metrics` e `/ping`) |
| `dynamic.yml` | routers `/observe/`, `/block/`, `/revoked/` (forwardAuth da spec 019 RF-04, `X-Traefix-Deny` da ADR 0074), `fs-plain` e `/ping`; backend no web do espelho (`http://170.247.40.86:8080`) sem conexões ociosas; modelo com `__FS_BLOCK_KEY__` e `__FS_REVOKED_KEY__` |
| `recorder/` | gravador em `127.0.0.1:18090` (o `export.url`): guarda cada lote (`NNNNNN.body` byte a byte e `NNNNNN.json` com cabeçalhos, sem `Authorization`, e a resposta do bot) e o repassa a `http://10.249.255.254:9003` sem mudar bytes nem cabeçalhos fim a fim; só stdlib |
| `up.sh` | sobe tudo por ssh e imprime os `export` do e2e |
| `down.sh` | desfaz tudo e confere a limpeza (sai ≠ 0 se algo ficou) |

## Uso

```sh
eval "$(test/traefix/up.sh)"                 # FS_TRAEFIX_STOP_BOT=1 e FS_TRAEFIX_SOCKS=127.0.0.1:18491 opcionais
go test -tags e2e -count=1 -v -run TestF8TraefixReal ./test/e2e/
test/traefix/down.sh
```

- O `up.sh` espera a trava `/tmp/fs-load-running` sumir (até `FS_TRAEFIX_LOCK_WAIT` s, padrão 3600), toma a trava com
  um token próprio e a segura até o `down.sh`: nenhuma carga, deploy nem `verify-full --e2e` corre junto.
- `docker pull` da `latest` a cada subida; o digest, o `traefik version` e o `sender` (`traefix/<versão>`) saem no
  stderr e no início do log do e2e. A imagem é apagada no `down.sh` se não existia antes.
- As chaves de teste (`fs-traefix-test-block-<ts>` `--mode block` e `fs-traefix-test-revoked-<ts>`, revogada na
  criação, domínio `finger-01.badblock.net.br`) são criadas pela CLI do bot no servidor e postas só no
  `run/dynamic.yml` de lá (modo 600); nunca passam pelo Mac nem entram no Git. O e2e cria e revoga a dele.
- Caso `relay` (task 313): abra antes `ssh -p 48022 -N -D 127.0.0.1:18491 root@finger-01.tmsoft.com.br` e passe
  `FS_TRAEFIX_SOCKS=127.0.0.1:18491` ao `up.sh`.
- Sem o `traefik:latest` de paridade (`FS_E2E_TRAEFIK_UPSTREAM_URL`), o caso `upstream-parity` pula; a paridade é da
  task 273 e exigiria um segundo container.
- O `down.sh` traz os lotes gravados para `tmp/traefix-test/<data>-<digest>/` (fora do Git; `FS_TRAEFIX_FETCH=0`
  pula). Eles têm o IP real do gerador: para virar `internal/bot/testdata/ingest/real/`, troque a origem por endereço
  de documentação como nas tasks 273 e 313.

## O que o ambiente toca no finger-01

Só `/finger-sniffer/var/traefix-test/` (fora do `rsync --delete` do deploy), o container `fs-traefix-test` (rede do
host, portas 18443/18444/18446/18447 e `127.0.0.1:18082`), o processo do gravador (`127.0.0.1:18090`, binário na
pasta), a imagem `tmsoftbrasil/traefix:latest`, as chaves `fs-traefix-test-*` e a trava. O `traefik-app`, os outros
containers e a rede do Docker não são tocados (ADR 0038 item 9); o `down.sh` confere que o `traefik-app` tem o mesmo
`StartedAt` e `RestartCount` de antes.

## Custo de CPU (spec 019 RF-11)

Não há gerador de custo aqui: a medida da task 273 (keep-alive, `GET /ping` em `ping@internal`, 30 s por entrada,
CPU pelo `cpu.stat` do cgroup do container) fica para quando for pedida de novo; as entradas `fsnoraw`, `fsh3o` e
`fsplain` já estão no `static.yml` para ela. CPU do container:
`cat /sys/fs/cgroup/system.slice/docker-$(docker inspect -f '{{.Id}}' fs-traefix-test).scope/cpu.stat`.
