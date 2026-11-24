- pkg/fingerprint/ja4: trecho ALPN da parte `a` pela definição publicada da FoxIO (igual ao tshark 4.4): hex quando o
  primeiro ou o último byte do primeiro protocolo não é `[0-9A-Za-z]`, no lugar do `9`/ASCII cru do `ja4` 0.18.6; o
  JA4 muda no registro, no feed e no bot para clientes com ALPN não alfanumérico (task 387).
