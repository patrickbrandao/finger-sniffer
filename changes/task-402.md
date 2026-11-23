- fix(bot): h3 casado com o fluxo QUIC do store sai com `view.tcp=false` (só o TTL, como nos ramos do traefix,
  ADR 0065 item 4), e o casamento traefix ↔ store confere o L4 (h3 → udp, h1/h2 → tcp) sem mudar a chave do índice:
  conexão TCP não casa mais com fluxo UDP da mesma origem e porta (task 402).
