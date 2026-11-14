- **raw**: em sessões TLS (porta `tls-*` e TLS automático), `half_close.server_sent_after_client_fin` passa a
  conferir ACK/RST no socket TCP aceito em vez de sair sempre `true`; cliente que fecha com `close()` após o
  close_notify agora registra `false` (task 148).
