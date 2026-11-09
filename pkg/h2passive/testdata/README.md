# Dados de teste do parser passivo h2

Derivados do `http2-with-cookies.pcapng` da FoxIO (Chrome contra www.youtube.com, com segredos TLS no pcapng),
que está completo em `pkg/fingerprint/ja4plus/testdata/` (licença BSD 3-Clause em `LICENSE-FoxIO-BSD3`):

- `chrome-foxio-in.bin`: bytes decifrados do sentido cliente → servidor (prefácio, SETTINGS, WINDOW_UPDATE e
  15 HEADERS), extraídos com `tshark -z follow,tls,raw,0` (tshark 4.4).
- `chrome-foxio-in.tshark.tsv`: por HEADERS do cliente, o que o tshark 4.4 decodifica: stream, nomes dos
  campos, representação HPACK, exclusivo, dependência e peso real (1..256).

Regenerar: `pkg/fingerprint/ja4plus/testdata/regen.sh`.
