- web/raw/h3: `tls.extension_errors` e `tls.field_errors` (`{field, offset, error}`, até 64 cada, códigos `duplicate`,
  `malformed` e `odd_length`) no evento `fs.v1.web.tls.client_hello` e no `TLSInfo` do registro, para extensão
  repetida ou malformada e `cipher_suites` ímpar no ClientHello (contrato 0.9.0, task 386).
