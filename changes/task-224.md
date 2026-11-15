- infra: scripts, CI e `.env.example` apontam para o finger-01 (ADR 0038): deploy e `linux_priv` em
  `root@finger-01.tmsoft.com.br:48022`, env com IPs, `ens192`, zona `finger-west-01.badblock.net.br`, certificados A/B,
  web em TCP 8080/8443 e UDP 8443, `FS_MAX_CONNS` 1000/250 e banco de 8 GiB; smoke em 8080/8443 com Alt-Svc
  `h3=":8443"` e o passo do traefik como AVISO (`SMOKE_TRAEFIK_REQUIRED=1` reprova) (task 224).
