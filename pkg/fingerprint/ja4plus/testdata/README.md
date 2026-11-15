# Dados de teste do JA4H

> **Servidor anterior (vps602).** Os gabaritos foram gerados na vps602 e ficam como registro; desde a ADR 0038 os
> scripts de regeneração apontam para o finger-01 (`root@finger-01.tmsoft.com.br`), que precisa das mesmas
> ferramentas (`tshark` 4.4, `p0f`, `ja4` em `/root/ja4-rust`).

- `http1-with-cookies.pcapng` e `http2-with-cookies.pcapng`: pcaps completos da FoxIO
  (`https://github.com/FoxIO-LLC/ja4`, pasta `pcap/`, commit `c6469a7b0dbf8fe963810162429fbfd9d1acc4d5`),
  licença BSD 3-Clause em `LICENSE-FoxIO-BSD3`. O h2 traz os segredos TLS no próprio pcapng (bloco DSB).
- `ja4h.golden.json`: saída da ferramenta oficial `ja4` (Rust, compilada na vps602 em `/root/ja4-rust`) com
  `-j`, `-j -r`, `-j -O` e `-j -r -O`, juntadas por requisição: `ja4h`, `ja4h_r`, `ja4h_o`, `ja4h_ro`.
- O teste do h2 lê o sentido do cliente já decifrado em `pkg/h2passive/testdata/chrome-foxio-in.bin`.

Regenerar: `./regen.sh` (precisa de ssh para a vps602, com tshark 4.4 e o `ja4` instalados).
