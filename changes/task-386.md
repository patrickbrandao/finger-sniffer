- pkg/tlsparse: extensão repetida no ClientHello fica crua em `Extensions`, mas todos os campos decodificados vêm da
  primeira ocorrência (JA4 com o primeiro ALPN e as `supported_versions` da primeira, como o `ja4` da FoxIO no caso
  da prova); repetições em `ExtensionErrors` e `cipher_suites` de tamanho ímpar em `FieldErrors` (task 386).
