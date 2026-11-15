- Página do espelho em `https://finger-01.badblock.net.br/` pelo traefik (TLS passthrough `HostSNI` até a 8443) e
  certificado B por TLS-ALPN-01 pelo mesmo caminho (staging e depois produção); `finger-01.tmsoft.com.br` sai do B.
  NAT do traefik no host (só 80/443/8081 e UDP 443) e o smoke passa a exigir a rota do traefik.
