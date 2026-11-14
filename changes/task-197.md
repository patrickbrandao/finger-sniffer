- test: golden sintéticos (`internal/store/testdata/synth/`, 42 pcaps) de `tcp.syn_mss`/`mtu_implied`/`mss_reduction`
  e de cada `ip.src_kind` com as bordas, pelo caminho real do store; `syn_mss` dos pcaps reais igual ao do tshark;
  e2e `TestSynMSSDirect` (curl IPv4/IPv6 à vps602, origem `global`) (task 197).
