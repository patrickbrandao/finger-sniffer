# Golden de ClientHello e h2 decifrado (task 036)

Capturas reais de curl, Go, Chrome e Firefox contra um servidor TLS + h2 temporário na vps602, com as chaves
TLS da sessão e as saídas das ferramentas de referência sobre o mesmo arquivo. Complementam os golden da
task 013 (`../pcaps/`), que só têm TCP e JA4T. Servem de gabarito para `pkg/tlsparse`, `pkg/fingerprint`
(JA3/JA4/JA4H/Akamai) e `pkg/h2passive`. O `golden_test.go` confere a coerência dos arquivos entre si e com o
tls.peet.ws, sem usar código do projeto.

## Casos

Coleta de 2026-11-09 (versões em `pcaps/VERSIONS.txt`: Chrome 156.0.8078.80, Firefox 159.0, Go 1.27.3,
curl 8.7.1/LibreSSL 3.3.6 do macOS, curl 8.23.0/OpenSSL 4.1.0 do Homebrew, macOS 27.0.1; tshark 4.4.19 e
ja4 0.18.6 na vps602).

| Caso | JA3 (tshark) | JA4 (ja4) | Akamai HTTP/2 (tshark) | JA4H (ja4) |
| --- | --- | --- | --- | --- |
| `curl-libressl-h2` | 375c6162a492dfbf2795909110ce8424 | t13d4907h2_0d8feac7bc37_7395dae3b2f3 | `3:100;4:10485760;2:0\|1048510465\|0\|m,s,a,p` | ge20nn020000_5594a17e7e7e_000000000000_000000000000 |
| `curl-libressl-h1` | 375c6162a492dfbf2795909110ce8424 | t13d4907h1_0d8feac7bc37_7395dae3b2f3 | — | ge11nn030000_fe444ad14866_000000000000_000000000000 |
| `curl-openssl-h2` | 9ff5f7c88ab8372852860f487a8b1dc5 | t13d3012h2_1d37bd780c83_581742d1f3c4 | `3:100;4:65536;2:0\|1048510465\|0\|m,s,a,p` | (não emitido, ver abaixo) |
| `curl-openssl-h1` | 9ff5f7c88ab8372852860f487a8b1dc5 | t13d3012h1_1d37bd780c83_581742d1f3c4 | — | ge11nn030000_fe444ad14866_000000000000_000000000000 |
| `go-h2` | 03117a8ed39ef02427ebbc39f121275c | t13d1312h2_f57a46bbacb6_f50d94e863eb | `2:0;4:4194304;5:1048576;6:10485760\|1073741824\|0\|a,m,p,s` | ge20nn020000_b89ce445e0b3_000000000000_000000000000 |
| `go-h1` | 9b7dcdf3f997f1fb7b4409c94cb7ef36 | t13d131100_f57a46bbacb6_f50d94e863eb | — | ge11nn030000_cd680697de12_000000000000_000000000000 |
| `chrome-h2` | 26f87593bb92874818103f1bc6624d34 | t13d1517h2_8daaf6152771_cb7bf5808d99 | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | ge20nn13ptbr_0c2c1d640f3e_000000000000_000000000000 |
| `chrome-h1` | edbecbe4e7261bbfe2f720652cdda341 | t13d1516h1_8daaf6152771_5b37b36a67c0 | — | ge11nn14ptbr_d9d4fb46dcb1_000000000000_000000000000 |
| `firefox-h2` | 9d42e90b0225e779f03141ddcd699df2 | t13d1517h2_8daaf6152771_3cbfd9057e0d | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s` | ge20nn10ptbr_d353d425b0bb_000000000000_000000000000 |
| `firefox-h1` | 9d42e90b0225e779f03141ddcd699df2 | t13d1517h1_8daaf6152771_3cbfd9057e0d | — | ge11nn11ptbr_0bc436807bd0_000000000000_000000000000 |

Os valores acima são os da primeira conexão de cada caso; o `ref.json` tem todas. O JA3 do Chrome muda a cada
conexão (ordem das extensões embaralhada), o JA4 não. O Go em h1 (`Transport.Protocols` só HTTP/1) não envia
ALPN, por isso o `00` no JA4.

Arquivos por caso em `pcaps/`:
- `<caso>.pcap`: captura `tcpdump -s0` na eth0, com o IP do Mac trocado por `198.51.100.10` (`../anon.py`)
  antes de qualquer saída de referência.
- `<caso>.keys`: chaves TLS da sessão (formato NSS SSLKEYLOGFILE), gravadas pelo `KeyLogWriter` do servidor.
  São de sessões descartáveis com um certificado autoassinado de 2 dias.
- `<caso>.tshark.json`: `tshark -T json --no-duplicate-keys -J 'tcp tls http2 http'` com as chaves e filtro
  `tls.handshake.type == 1 || http2 || http`: ClientHello inteiro (inclui `tls.handshake.ja3*` e `ja4*`),
  SETTINGS em ordem, WINDOW_UPDATE, PRIORITY, flags de prioridade do HEADERS e o HPACK decodificado
  (`http2.header.name`, `value`, `repr`, `index`).
- `<caso>.ja4.jsonl`: `ja4 -j -r --keylog-file` da FoxIO: JA4, JA4_r, JA4S, JA4X, JA4L e JA4H (h1 e h2).
- `<caso>.ref.json`: resumo gerado por `ref.py` só com saídas das ferramentas: ClientHellos (JA3/JA4 do tshark
  e do ja4, SNI, ALPN), frames h2 do cliente por conexão, Akamai por conexão (`S[;]|WU|P[,]|PS[,]`, técnica do
  fingerproxy, montado com os campos do tshark), JA4H do ja4.
- `<caso>.client.h2` (casos h2): bytes h2 decifrados do cliente na conexão principal (`follow,tls,raw` do
  tshark), do prefácio em diante.

Referência externa: `pcaps/<cliente>.peet.json` é a resposta de `https://tls.peet.ws/api/all` para o mesmo
binário (Chrome pelo `--dump-dom`), coletada em `pcaps/peet.date` (2026-11-09T03:04Z), também sem o IP do Mac.

Cópia mínima para o parser passivo em `pkg/h2passive/testdata/clients/`: `<caso>.client.h2` e
`<caso>.expected.json` (o `ref.json` sem os ClientHellos) dos cinco casos h2.

## Conferências e achados

- **Akamai**: o montado do tshark bate com o do tls.peet.ws, na mesma coleta, para Chrome 156, curl LibreSSL,
  curl OpenSSL e Go (`TestAkamaiMatchesPeet`). O do **Firefox 159 não foi conferido externamente**: o Firefox
  headless conecta e faz as requisições (a rede roda no processo pai), mas os processos de conteúdo não sobem
  no ambiente da coleta (`sandbox_extension_issue_file_to_process failed ... Operation not permitted`, o
  "channel error" da task 013), então não há página para ler a resposta do tls.peet.ws. A sandbox não foi
  desligada. O valor do pcap decifrado é o mesmo padrão já conhecido do Firefox (sem frames PRIORITY,
  pseudo-cabeçalhos `m,p,a,s`). O scrapfly não foi usado; o tls.peet.ws basta para os outros quatro.
- **JA4 do tshark 4.4.19 diverge no Chrome**: o tshark mantém o GREASE dos algoritmos de assinatura no JA4_r
  (ex. `_fafa,0904,...`) e a parte c do hash muda. O ja4 da FoxIO e o tls.peet.ws descartam o GREASE e
  concordam. Por isso o JA4 de referência é o do ja4 (`ja4_tool` no `ref.json`), e `TestClientHelloTsharkVsJA4`
  só aceita diferença na parte c quando há GREASE nesse campo.
- **tls.peet.ws escreve a contagem de extensões sem zero à esquerda** para o curl LibreSSL (`t13d497h2`, 49
  cifras e 7 extensões); o certo, pela especificação da FoxIO, é `t13d4907h2`, como o ja4 e o tshark calculam.
- **ja4 0.18.6 não emite JA4H em `curl-openssl-h2`**: o curl com OpenSSL manda prefácio, SETTINGS,
  WINDOW_UPDATE e HEADERS no mesmo registro TLS, e o ja4 não acha o HEADERS. O tshark decodifica o HEADERS
  (`ref.json`); os campos são os mesmos do `curl-libressl-h2` (GET h2, `user-agent` e `accept`, sem cookie nem
  `accept-language`), então o JA4H esperado é o mesmo: `ge20nn020000_5594a17e7e7e_000000000000_000000000000`.
- Os bytes de `pkg/h2passive/testdata/clients/*.client.h2` têm a mesma sequência de frames (tipo, flags,
  stream, tamanho), os mesmos SETTINGS e o mesmo WINDOW_UPDATE que o tshark dissecou
  (`TestClientH2BytesMatchTshark`).

## Como regenerar

```bash
test/golden/tls/collect.sh                          # todos os casos e o tls.peet.ws
ONLY="chrome-h2 firefox-h2" test/golden/tls/collect.sh  # só alguns casos (sem tls.peet.ws)
```

O script roda no Mac e usa a vps602 sem aprovação, por ser o servidor de testes. Passos:
- gera um certificado autoassinado ECDSA P-256 para `vps602.tmsoft.com.br` (2 dias);
- compila `server/` para linux/amd64 (tag `golden`) e o copia para `/tmp/fs-golden-tls` na vps602;
- para cada caso, sobe o servidor na porta capturada 7702 com um keylog só desse caso e um `tcpdump -s0` na
  eth0 filtrando pelo IP do Mac; roda o cliente; para os dois;
- confiança no certificado, sempre restrita a ele: `--cacert` no curl, `-ca` no Go (`goclient/`), o hash da
  chave em `--ignore-certificate-errors-spki-list` no Chrome e uma exceção em `cert_override.txt` num perfil
  descartável do Firefox. Nada no sistema muda e nenhuma sandbox é desligada;
- h1: `--http1.1` no curl, `-proto h1` no Go, `--disable-http2` no Chrome e
  `network.http.http2.enabled=false` no Firefox;
- na vps602: `anon.py`, tshark, ja4 e `ref.py`; copia tudo para `pcaps/` e a cópia mínima para
  `pkg/h2passive/testdata/clients/`;
- consulta o tls.peet.ws com os mesmos binários.

No fim, mesmo em erro, o script para o servidor e o tcpdump, apaga `/tmp/fs-golden-tls` e confere a limpeza. O
log mostra "vps602 limpa: sem servidor, sem tcpdump, sem listener na 7702 e sem /tmp/fs-golden-tls".

Pré-requisitos: na vps602, `tshark` 4.4 e `tcpdump` (apt) e o ja4 da FoxIO em `/root/ja4-rust` (ver
`../README.md`); no Mac, Go, `/usr/bin/curl`, o curl do Homebrew (opcional, `CURL_OPENSSL`), Chrome e Firefox.
