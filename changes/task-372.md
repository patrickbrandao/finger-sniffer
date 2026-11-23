- bot: o webhook não segue redirecionamento (3xx é resposta final, sem nova tentativa) e o cliente próprio recusa,
  depois da resolução, loopback, redes privadas, link-local, CGNAT, multicast, faixas reservadas e os IPs do host;
  `key create` recusa `--webhook-url` com IP literal interno (task 372, itens 1, 2, 4 e 5).
