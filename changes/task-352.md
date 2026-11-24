- fix(infra): journal próprio do espelho (ADR 0075 item 3): `LogNamespace=finger-sniffer` nas 8 units com processo e
  `/etc/systemd/journald@finger-sniffer.conf` com 24 h / 200 MB; o deploy apaga o drop-in antigo que limitava o journal
  do host inteiro. Leitura: `journalctl --namespace=finger-sniffer -u 'finger-sniffer-*'` (task 352).
