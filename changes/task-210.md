- dns: as opções EDNS do evento `fs.v1.dns.query` saem da RDATA do OPT (pelo `Rdlength`), não de um
  cabeçalho fixo de 11 bytes; OPT com nome fora da raiz não gera mais opções de lixo nem perde as reais
  (task 210).
