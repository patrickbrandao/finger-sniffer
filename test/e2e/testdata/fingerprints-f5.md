# Conferência FoxIO/tshark consolidada (task 067)

Gerado por `TestF5Fingerprints` (`test/e2e/f5_fingerprints_test.go`) com `FS_E2E_UPDATE=1`. Cada impressão
do registro (`GET /api/v1/connections/{id}`) é comparada com o `ja4` da FoxIO e o `tshark` aplicados ao **mesmo
pcap**, o de `GET /api/v1/connections/{id}/pcap`, com o keylog do próprio cliente. `—` = a ferramenta não
calcula essa impressão. JA4T e p0f vêm do SYN; o p0f é conferido com `p0f -r` sobre o mesmo pcap.

- Data: 2026-11-09 09:02Z; serviços na vps602 no commit 8428b21, 9d18a32, d91c354.
- Ferramentas na vps602: TShark (Wireshark) 4.4.19; ja4 0.18.6; p0f 3.09b-4.
- Clientes (macOS 27.0.1): curl 8.23.0 (aarch64-apple-darwin27.0.0) libcurl/8.23.0 OpenSSL/4.1.0 zlib/1.2.12 brotli/1.2.1 zstd/1.5.7 AppleIDN libpsl/0.23.3 libssh2/1.11.1 nghttp2/1.71.0 ngtcp2/1.26.0 nghttp3/1.19.0 mit-krb5/1.7-prerelease OpenLDAP/2.4.28/Apple; curl 8.7.1 (x86_64-apple-darwin26.0) libcurl/8.7.1 (SecureTransport) LibreSSL/3.3.6 zlib/1.2.12 nghttp2/1.69.0; HTTP/3 pelo /opt/homebrew/opt/curl/bin/curl; Go 1.27.3 (net/http e quic-go); Google Chrome 156.0.8078.80; Mozilla Firefox 159.0.
- Chrome e Firefox headless com o sandbox ligado. h3: Chrome com `--origin-to-force-quic-on=<host>:443`,
  Firefox com `network.http.http3.alt-svc-mapping-for-testing` no perfil descartável; TCP: QUIC desligado.
- `curl-libressl` (curl do macOS) não grava SSLKEYLOGFILE: Akamai e JA4H sem referência; os demais campos
  conferidos. A tabela mostra a primeira conexão com dados de cada cliente; as demais (preconnect do Chrome)
  foram conferidas do mesmo jeito.

## Resumo

| Cliente | JA3 | JA3N | JA4 | JA4_r | JA4_o | JA4T | p0f | Akamai | JA4H | JA4 q |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| curl-openssl h2 | igual | igual | igual | igual | igual | igual | igual | igual | igual¹ | — |
| curl-openssl h1 | igual | igual | igual | igual | igual | igual | igual | — | igual | — |
| curl-libressl h2 | igual | igual | igual | igual | igual | igual | igual | sem ref. | sem ref. | — |
| go h2 | igual | igual | igual | igual | igual | igual | igual | igual | igual | — |
| go h1 | igual | igual | igual | igual | igual | igual | igual | — | igual | — |
| chrome h2 | igual | igual | igual¹ | igual¹ | igual | igual | igual | igual | igual | — |
| chrome h1 | igual | igual | igual¹ | igual¹ | igual | igual | igual | — | igual | — |
| firefox h2 | igual | igual | igual | igual | igual | igual | igual | igual | igual | — |
| firefox h1 | igual | igual | igual | igual | igual | igual | igual | — | igual | — |
| curl h3 | — | — | — | — | — | — | — | — | sem ref. | igual |
| quic-go h3 | — | — | — | — | — | — | — | — | sem ref. | igual |
| chrome h3 | — | — | — | — | — | — | — | — | sem ref. | igual |
| firefox h3 | — | — | — | — | — | — | — | — | sem ref. | igual |

¹ igual à referência válida, com divergência conhecida de uma das ferramentas (detalhe abaixo).
JA3N: o tshark não calcula; a referência é o `ja3_full` do tshark com as extensões em ordem numérica.
JA4H h3: sem referência externa (nem o `ja4` nem o `tshark` calculam); os campos QPACK são conferidos com o
tshark no caso 12 (`f4_h3_test.go`).

## Detalhe

| Cliente | Impressão | Registro | FoxIO `ja4` | tshark | Resultado |
| --- | --- | --- | --- | --- | --- |
| curl-openssl h2 | JA3 | `771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47,65281-11-10-22-23-49-13-43-45-51-0-16,4588-4587-4590-29-23-30-24-25-41-256-257,0` | — | = registro | igual |
| curl-openssl h2 | JA3 MD5 | `9ff5f7c88ab8372852860f487a8b1dc5` | — | = registro | igual |
| curl-openssl h2 | JA3N | `771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47,0-10-11-13-16-22-23-43-45-49-51-65281,4588-4587-4590-29-23-30-24-25-41-256-257,0` | — | = registro | igual (tshark: ja3_full com extensões ordenadas) |
| curl-openssl h2 | JA3N MD5 | `453717a71fd1e765fc27de1ff122593e` | — | = registro | igual |
| curl-openssl h2 | JA4 | `t13d3012h2_1d37bd780c83_581742d1f3c4` | = registro | = registro | igual |
| curl-openssl h2 | JA4_r | `t13d3012h2_002f,0033,0035,0039,003c,003d,0067,006b,009c,009d,009e,009f,1301,1302,1303,c009,c00a,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030,cca8,cca9,ccaa_000a,000b,000d,0016,0017,002b,002d,0031,0033,ff01_0905,0906,0904,0403,0503,0603,0807,0808,081a,081b,081c,0809,080a,080b,0804,0805,0806,0401,0501,0601,0303,0301,0302,0402,0502,0602,0911,0912,0913,0914,0915,0916,0917,0918,0919,091a,091b,091c,0708` | = registro | = registro | igual |
| curl-openssl h2 | JA4_o | `t13d3012h2_8d44cdc55eec_cc054aaa427e` | = registro | — | igual |
| curl-openssl h2 | JA4T | `65535_2-1-3-1-1-8-4-0-0_1412_6` | = registro | — | igual |
| curl-openssl h2 | p0f | `4:46+18:0:1412:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0` | — | — | igual ao `p0f -r` |
| curl-openssl h2 | Akamai | `3:100;4:65536;2:0\|1048510465\|0\|m,s,a,p` | — | = registro | igual |
| curl-openssl h2 | JA4H (h2) | `ge20nn020000_5594a17e7e7e_000000000000_000000000000` | — | — | ja4 não emite (limitação do ja4 0.18.6 com prefácio e HEADERS no mesmo registro TLS, task 036) |
| curl-openssl h1 | JA3 | `771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47,65281-11-10-22-23-49-13-43-45-51-0-16,4588-4587-4590-29-23-30-24-25-41-256-257,0` | — | = registro | igual |
| curl-openssl h1 | JA3 MD5 | `9ff5f7c88ab8372852860f487a8b1dc5` | — | = registro | igual |
| curl-openssl h1 | JA3N | `771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47,0-10-11-13-16-22-23-43-45-49-51-65281,4588-4587-4590-29-23-30-24-25-41-256-257,0` | — | = registro | igual (tshark: ja3_full com extensões ordenadas) |
| curl-openssl h1 | JA3N MD5 | `453717a71fd1e765fc27de1ff122593e` | — | = registro | igual |
| curl-openssl h1 | JA4 | `t13d3012h1_1d37bd780c83_581742d1f3c4` | = registro | = registro | igual |
| curl-openssl h1 | JA4_r | `t13d3012h1_002f,0033,0035,0039,003c,003d,0067,006b,009c,009d,009e,009f,1301,1302,1303,c009,c00a,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030,cca8,cca9,ccaa_000a,000b,000d,0016,0017,002b,002d,0031,0033,ff01_0905,0906,0904,0403,0503,0603,0807,0808,081a,081b,081c,0809,080a,080b,0804,0805,0806,0401,0501,0601,0303,0301,0302,0402,0502,0602,0911,0912,0913,0914,0915,0916,0917,0918,0919,091a,091b,091c,0708` | = registro | = registro | igual |
| curl-openssl h1 | JA4_o | `t13d3012h1_8d44cdc55eec_cc054aaa427e` | = registro | — | igual |
| curl-openssl h1 | JA4T | `65535_2-1-3-1-1-8-4-0-0_1412_6` | = registro | — | igual |
| curl-openssl h1 | p0f | `4:46+18:0:1412:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0` | — | — | igual ao `p0f -r` |
| curl-openssl h1 | JA4H (h1) | `ge11nn030000_fe444ad14866_000000000000_000000000000` | = registro | — | igual |
| curl-libressl h2 | JA3 | `771,4867-4866-4865-52393-52392-52394-49200-49196-49192-49188-49172-49162-159-107-57-65413-196-136-129-157-61-53-192-132-49199-49195-49191-49187-49171-49161-158-103-51-190-69-156-60-47-186-65-49169-49159-5-4-49170-49160-22-10-255,43-51-0-11-10-13-16,29-23-24-25,0` | — | = registro | igual |
| curl-libressl h2 | JA3 MD5 | `375c6162a492dfbf2795909110ce8424` | — | = registro | igual |
| curl-libressl h2 | JA3N | `771,4867-4866-4865-52393-52392-52394-49200-49196-49192-49188-49172-49162-159-107-57-65413-196-136-129-157-61-53-192-132-49199-49195-49191-49187-49171-49161-158-103-51-190-69-156-60-47-186-65-49169-49159-5-4-49170-49160-22-10-255,0-10-11-13-16-43-51,29-23-24-25,0` | — | = registro | igual (tshark: ja3_full com extensões ordenadas) |
| curl-libressl h2 | JA3N MD5 | `90a369ebd76665d3296677774ee22ea2` | — | = registro | igual |
| curl-libressl h2 | JA4 | `t13d4907h2_0d8feac7bc37_7395dae3b2f3` | = registro | = registro | igual |
| curl-libressl h2 | JA4_r | `t13d4907h2_0004,0005,000a,0016,002f,0033,0035,0039,003c,003d,0041,0045,0067,006b,0081,0084,0088,009c,009d,009e,009f,00ba,00be,00c0,00c4,00ff,1301,1302,1303,c007,c008,c009,c00a,c011,c012,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030,cca8,cca9,ccaa,ff85_000a,000b,000d,002b,0033_0806,0601,0603,0805,0501,0503,0804,0401,0403,0201,0203` | = registro | = registro | igual |
| curl-libressl h2 | JA4_o | `t13d4907h2_2677ac475d6b_c6f9150fbe3b` | = registro | — | igual |
| curl-libressl h2 | JA4T | `65535_2-1-3-1-1-8-4-0-0_1412_6` | = registro | — | igual |
| curl-libressl h2 | p0f | `4:46+18:0:1412:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0` | — | — | igual ao `p0f -r` |
| curl-libressl h2 | Akamai | `3:100;4:10485760;2:0\|1048510465\|0\|m,s,a,p` | — | — | sem referência: cliente sem SSLKEYLOGFILE |
| curl-libressl h2 | JA4H (h2) | `ge20nn020000_5594a17e7e7e_000000000000_000000000000` | — | — | sem referência: cliente sem SSLKEYLOGFILE |
| go h2 | JA3 | `771,49195-49199-49196-49200-52393-52392-49161-49171-49162-49172-4865-4866-4867,0-11-65281-23-18-5-10-13-50-16-43-51,4588-4587-4589-29-23-24-25,0` | — | = registro | igual |
| go h2 | JA3 MD5 | `03117a8ed39ef02427ebbc39f121275c` | — | = registro | igual |
| go h2 | JA3N | `771,49195-49199-49196-49200-52393-52392-49161-49171-49162-49172-4865-4866-4867,0-5-10-11-13-16-18-23-43-50-51-65281,4588-4587-4589-29-23-24-25,0` | — | = registro | igual (tshark: ja3_full com extensões ordenadas) |
| go h2 | JA3N MD5 | `71cf1fa4fbf38beb19085420f04107f7` | — | = registro | igual |
| go h2 | JA4 | `t13d1312h2_f57a46bbacb6_a089bac06eae` | = registro | = registro | igual |
| go h2 | JA4_r | `t13d1312h2_1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,002b,0032,0033,ff01_0904,0905,0906,0804,0403,0807,0805,0806,0401,0501,0601,0503,0603,0201,0203` | = registro | = registro | igual |
| go h2 | JA4_o | `t13d1312h2_45672f90a73c_d0dea502ed1f` | = registro | — | igual |
| go h2 | JA4T | `65535_2-1-3-1-1-8-4-0-0_1412_6` | = registro | — | igual |
| go h2 | p0f | `4:46+18:0:1412:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0` | — | — | igual ao `p0f -r` |
| go h2 | Akamai | `2:0;4:4194304;5:1048576;6:10485760\|1073741824\|0\|a,m,p,s` | — | = registro | igual |
| go h2 | JA4H (h2) | `ge20nn020000_b89ce445e0b3_000000000000_000000000000` | = registro | — | igual |
| go h1 | JA3 | `771,49195-49199-49196-49200-52393-52392-49161-49171-49162-49172-4865-4866-4867,0-11-65281-23-18-5-10-13-50-43-51,4588-4587-4589-29-23-24-25,0` | — | = registro | igual |
| go h1 | JA3 MD5 | `9b7dcdf3f997f1fb7b4409c94cb7ef36` | — | = registro | igual |
| go h1 | JA3N | `771,49195-49199-49196-49200-52393-52392-49161-49171-49162-49172-4865-4866-4867,0-5-10-11-13-18-23-43-50-51-65281,4588-4587-4589-29-23-24-25,0` | — | = registro | igual (tshark: ja3_full com extensões ordenadas) |
| go h1 | JA3N MD5 | `849eb27b00bd981b4c584115e49d941a` | — | = registro | igual |
| go h1 | JA4 | `t13d131100_f57a46bbacb6_a089bac06eae` | = registro | = registro | igual |
| go h1 | JA4_r | `t13d131100_1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,002b,0032,0033,ff01_0904,0905,0906,0804,0403,0807,0805,0806,0401,0501,0601,0503,0603,0201,0203` | = registro | = registro | igual |
| go h1 | JA4_o | `t13d131100_45672f90a73c_ec51838167ee` | = registro | — | igual |
| go h1 | JA4T | `65535_2-1-3-1-1-8-4-0-0_1412_6` | = registro | — | igual |
| go h1 | p0f | `4:46+18:0:1412:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0` | — | — | igual ao `p0f -r` |
| go h1 | JA4H (h1) | `ge11nn030000_cd680697de12_000000000000_000000000000` | = registro | — | igual |
| chrome h2 | JA3 | `771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,17613-43-16-27-65281-51764-51-45-5-11-13-35-23-0-18-65037-10,4588-29-23-24,0` | — | = registro | igual |
| chrome h2 | JA3 MD5 | `d98963ec031d629de772d8dc083ed8b1` | — | = registro | igual |
| chrome h2 | JA3N | `771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17613-51764-65037-65281,4588-29-23-24,0` | — | = registro | igual (tshark: ja3_full com extensões ordenadas) |
| chrome h2 | JA3N MD5 | `bd4930bd9b000ee684830e44bab76fdf` | — | = registro | igual |
| chrome h2 | JA4 | `t13d1517h2_8daaf6152771_cb7bf5808d99` | = registro | `t13d1517h2_8daaf6152771_a323378790d4` | igual ao ja4; tshark diverge: mantém GREASE nos algoritmos de assinatura (limitação do tshark 4.4, task 036) |
| chrome h2 | JA4_r | `t13d1517h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,ca34,fe0d,ff01_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601` | = registro | `t13d1517h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,ca34,fe0d,ff01_3a3a,0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601` | igual ao ja4; tshark diverge: mantém GREASE nos algoritmos de assinatura (limitação do tshark 4.4, task 036) |
| chrome h2 | JA4_o | `t13d1517h2_acb858a92679_a3070a33504f` | = registro | — | igual |
| chrome h2 | JA4T | `65535_2-1-3-1-1-8-4-0-0_1412_6` | = registro | — | igual |
| chrome h2 | p0f | `4:46+18:0:1412:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0` | — | — | igual ao `p0f -r` |
| chrome h2 | Akamai | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | — | = registro | igual |
| chrome h2 | JA4H (h2) | `ge20nn13ptbr_0c2c1d640f3e_000000000000_000000000000 ge20nr11ptbr_33778c32ea55_000000000000_000000000000` | = registro | — | igual (2 requisições) |
| chrome h1 | JA3 | `771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-65037-18-51764-11-16-23-35-5-13-43-45-65281-10-51-27,4588-29-23-24,0` | — | = registro | igual |
| chrome h1 | JA3 MD5 | `87d33bfa0fce64bf0e9f1907821bb2a8` | — | = registro | igual |
| chrome h1 | JA3N | `771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-51764-65037-65281,4588-29-23-24,0` | — | = registro | igual (tshark: ja3_full com extensões ordenadas) |
| chrome h1 | JA3N MD5 | `11a7f5f23ec2a0977c070e6bf5b708c8` | — | = registro | igual |
| chrome h1 | JA4 | `t13d1516h1_8daaf6152771_5b37b36a67c0` | = registro | `t13d1516h1_8daaf6152771_3a9a3f345507` | igual ao ja4; tshark diverge: mantém GREASE nos algoritmos de assinatura (limitação do tshark 4.4, task 036) |
| chrome h1 | JA4_r | `t13d1516h1_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,ca34,fe0d,ff01_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601` | = registro | `t13d1516h1_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,ca34,fe0d,ff01_fafa,0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601` | igual ao ja4; tshark diverge: mantém GREASE nos algoritmos de assinatura (limitação do tshark 4.4, task 036) |
| chrome h1 | JA4_o | `t13d1516h1_acb858a92679_bbf0668a1039` | = registro | — | igual |
| chrome h1 | JA4T | `65535_2-1-3-1-1-8-4-0-0_1412_6` | = registro | — | igual |
| chrome h1 | p0f | `4:46+18:0:1412:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0` | — | — | igual ao `p0f -r` |
| chrome h1 | JA4H (h1) | `ge11nn14ptbr_d9d4fb46dcb1_000000000000_000000000000 ge11nr12ptbr_94cd318220e6_000000000000_000000000000` | = registro | — | igual (2 requisições) |
| firefox h2 | JA3 | `771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25,0` | — | = registro | igual |
| firefox h2 | JA3 MD5 | `9d42e90b0225e779f03141ddcd699df2` | — | = registro | igual |
| firefox h2 | JA3N | `771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-28-34-35-43-45-51-65037-65281,4588-29-23-24-25,0` | — | = registro | igual (tshark: ja3_full com extensões ordenadas) |
| firefox h2 | JA3N MD5 | `f9c6a2c424206e61efb6c1a6325596b5` | — | = registro | igual |
| firefox h2 | JA4 | `t13d1517h2_8daaf6152771_3cbfd9057e0d` | = registro | = registro | igual |
| firefox h2 | JA4_r | `t13d1517h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0023,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201` | = registro | = registro | igual |
| firefox h2 | JA4_o | `t13d1517h2_77608d807651_df135d36b6d5` | = registro | — | igual |
| firefox h2 | JA4T | `65535_2-1-3-1-1-8-4-0-0_1412_6` | = registro | — | igual |
| firefox h2 | p0f | `4:46+18:0:1412:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0` | — | — | igual ao `p0f -r` |
| firefox h2 | Akamai | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s` | — | = registro | igual |
| firefox h2 | JA4H (h2) | `ge20nn10ptbr_d353d425b0bb_000000000000_000000000000` | = registro | — | igual |
| firefox h1 | JA3 | `771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25,0` | — | = registro | igual |
| firefox h1 | JA3 MD5 | `9d42e90b0225e779f03141ddcd699df2` | — | = registro | igual |
| firefox h1 | JA3N | `771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-28-34-35-43-45-51-65037-65281,4588-29-23-24-25,0` | — | = registro | igual (tshark: ja3_full com extensões ordenadas) |
| firefox h1 | JA3N MD5 | `f9c6a2c424206e61efb6c1a6325596b5` | — | = registro | igual |
| firefox h1 | JA4 | `t13d1517h1_8daaf6152771_3cbfd9057e0d` | = registro | = registro | igual |
| firefox h1 | JA4_r | `t13d1517h1_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0023,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201` | = registro | = registro | igual |
| firefox h1 | JA4_o | `t13d1517h1_77608d807651_df135d36b6d5` | = registro | — | igual |
| firefox h1 | JA4T | `65535_2-1-3-1-1-8-4-0-0_1412_6` | = registro | — | igual |
| firefox h1 | p0f | `4:46+18:0:1412:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0` | — | — | igual ao `p0f -r` |
| firefox h1 | JA4H (h1) | `ge11nn11ptbr_0bc436807bd0_000000000000_000000000000` | = registro | — | igual |
| curl h3 | JA4 q | `q13d0311h3_55b375c5d22e_df5ee7f3ca36` | = registro | = registro | igual |
| curl h3 | JA4_r q | `q13d0311h3_1301,1302,1303_000a,000d,0016,0017,002b,002d,0031,0033,0039_0905,0906,0904,0403,0503,0603,0807,0808,081a,081b,081c,0809,080a,080b,0804,0805,0806,0401,0501,0601,0911,0912,0913,0914,0915,0916,0917,0918,0919,091a,091b,091c,0708` | = registro | = registro | igual |
| curl h3 | JA4_o q | `q13d0311h3_0ce35177f2fe_529c51d8652a` | = registro | — | igual |
| curl h3 | JA4H (h3) | `ge30nn020000_5594a17e7e7e_000000000000_000000000000` | — | — | sem referência: ja4 0.18.6 e tshark 4.4 não calculam JA4H em h3 |
| quic-go h3 | JA4 q | `q13d0313h3_55b375c5d22e_4156cdf64688` | = registro | = registro | igual |
| quic-go h3 | JA4_r q | `q13d0313h3_1301,1302,1303_0005,000a,000b,000d,0012,0017,002b,0032,0033,0039,ff01_0904,0905,0906,0804,0403,0807,0805,0806,0503,0603` | = registro | = registro | igual |
| quic-go h3 | JA4_o q | `q13d0313h3_55b375c5d22e_c26102b63aab` | = registro | — | igual |
| quic-go h3 | JA4H (h3) | `ge30nn020000_b89ce445e0b3_000000000000_000000000000` | — | — | sem referência: ja4 0.18.6 e tshark 4.4 não calculam JA4H em h3 |
| chrome h3 | JA4 q | `q13d0312h3_55b375c5d22e_178839b6cec1` | = registro | = registro | igual |
| chrome h3 | JA4_r q | `q13d0312h3_1301,1302,1303_000a,000d,001b,002b,002d,0033,0039,44cd,ca34,fe0d_0403,0804,0401,0503,0805,0501,0806,0601,0201` | = registro | = registro | igual |
| chrome h3 | JA4_o q | `q13d0312h3_55b375c5d22e_9fdce59d84df` | = registro | — | igual |
| chrome h3 | JA4H (h3) | `ge30nn13ptbr_0c2c1d640f3e_000000000000_000000000000` | — | — | sem referência: ja4 0.18.6 e tshark 4.4 não calculam JA4H em h3 |
| firefox h3 | JA4 q | `q13d0315h3_55b375c5d22e_dc5437974b47` | = registro | = registro | igual |
| firefox h3 | JA4_r q | `q13d0315h3_1301,1302,1303_0005,000a,000d,0017,001b,001c,0022,002b,002d,0033,0039,fe0d,ff01_0403,0503,0603,0203,0804,0805,0806,0401,0501,0601,0201` | = registro | = registro | igual |
| firefox h3 | JA4_o q | `q13d0315h3_85902d7a8465_18f493b99034` | = registro | — | igual |
| firefox h3 | JA4H (h3) | `ge30nn10ptbr_4584a0009685_000000000000_000000000000` | — | — | sem referência: ja4 0.18.6 e tshark 4.4 não calculam JA4H em h3 |

Conexões conferidas: chrome h1 (2 conexões), chrome h2 (2 conexões), chrome h3 (1 conexões), curl h3 (1 conexões), curl-libressl h2 (1 conexões), curl-openssl h1 (1 conexões), curl-openssl h2 (1 conexões), firefox h1 (3 conexões), firefox h2 (2 conexões), firefox h3 (1 conexões), go h1 (1 conexões), go h2 (1 conexões), quic-go h3 (1 conexões). Linhas com divergência não justificada: 0.
