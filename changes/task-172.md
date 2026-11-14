- infra: o deploy grava por unit o hash da configuração aplicada (unit + env ou `nats.conf`) em
  `/finger-sniffer/etc/applied/`; o deploy completo seguinte a um `SVC=` reinicia quem tiver configuração
  instalada e ainda não aplicada, inclusive o NATS (task 172).
