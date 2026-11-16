# Fingerprints do ingest (task 277)

Entradas do teste `TestIngestFingerprintsGolden`, copiadas dos goldens do espelho para o pacote não depender de
caminhos de outros donos:

- `tls/<caso>.bin`: ClientHello cru (registros TLS), de `pkg/tlsparse/testdata/` (os `foxio-*` vêm dos pcaps da
  FoxIO, licença BSD 3-Clause em `LICENSE-FoxIO-BSD3`).
- `h2/<caso>.prefix`: bytes do cliente depois do prefácio até o fim do primeiro HEADERS (o `h2_prefix` da spec 019
  RF-03), cortados de `pkg/h2passive/testdata/clients/<caso>-h2.client.h2`.
- `golden.json`: JA3/JA3 MD5 (`ja3.golden.json`), JA4/JA4_r/JA4_o (`ja4.golden.json`, ja4 da FoxIO) de
  `pkg/fingerprint/internal/pcaptest/testdata/tls/` e o Akamai dos `*.expected.json` do h2passive (tshark 4.4).

O teste também confere que o resultado é igual ao que o web calcula para os mesmos bytes (mesma sequência de
chamadas de `internal/web/conn.go` e `internal/web/h2_events.go`).
