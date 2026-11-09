# Golden pcaps (task 013)

Capturas reais de clientes conhecidos contra a vps602, com as saídas das ferramentas de referência sobre o
mesmo arquivo. Usadas por `internal/store/golden_test.go`. Esse teste passa cada pcap pelo ingest e confere
o registro de cada conexão:
- RTT do handshake contra o `tcp.analysis.ack_rtt` do tshark, com diferença menor que 0,1 ms;
- segmentos, retransmissões e keepalives por sentido contra o tshark;
- JA4T contra o `ja4`;
- assinatura e SO contra o `p0f -r`. A conferência do SO só acontece com `FS_P0F_DB` definido ou com o
  `p0f.fp` do deploy presente.

## Casos

| Pcap | Cliente | O que exercita |
| --- | --- | --- |
| `curl-macos-v4` / `curl-macos-v6` | curl do macOS, download de 400 KB | pilha macOS IPv4 e IPv6, delayed ACK |
| `curl-linux-v4` / `curl-linux-v6` | curl da vps602 (Debian 13) para `example.com:80` | pilha Linux IPv4 e IPv6 (cliente = VPS, saída pela eth0) |
| `go-macos` | `net/http` do Go (`goclient/`) | cliente Go |
| `chrome-macos` | Chrome headless (`--dump-dom`) | Chrome, várias conexões (preconnect) |
| `firefox-macos` | Firefox headless (`--screenshot`) | Firefox |
| `keepalive-macos` | socket com keepalive TCP de 1 s, parado ~4,5 s (`sock.py keepalive`) | sondas de keepalive |
| `retransmit-macos` | curl com perda de 8% nos pacotes que saem da porta 7700 (`tc netem`) | retransmissões do espelho |
| `rst-macos` | socket que fecha com `SO_LINGER 0` (`sock.py rst`) | fechamento por RST |
| `windows-foxio` | cliente Windows 10/11 real (navegador e serviços do sistema), captura pública da FoxIO | pilha Windows (JA4T `64240_2-1-3-1-1-4_1460_8`, p0f `Windows NT kernel`), ICMP "fragmentation needed" no meio de um fluxo (task 088) |

O `windows-foxio` não foi capturado contra a vps602: o projeto não tem máquina Windows. Ele vem do
`latest.pcapng` dos pcaps de teste da FoxIO (`https://github.com/FoxIO-LLC/ja4`, pasta `pcap/`, commit
`c6469a7b0dbf8fe963810162429fbfd9d1acc4d5`, licença BSD 3-Clause, cópia em
`pkg/fingerprint/internal/pcaptest/testdata/syn/LICENSE-FoxIO-BSD3`), capturado no próprio cliente Windows
(TTL 128, MSS 1460, wscale 8, sem timestamps). `foxio-windows.sh` deixa só os 6 fluxos TCP com SYN, converte
para pcap e gera as três saídas de referência na vps602 (mesmos campos do `collect.sh`; `p0f -r` com o
`p0f.fp` do deploy). Os IPs são o privado do cliente e os de servidores públicos da captura original, por
isso não passam pelo `anon.py`. O teste ignora os erros ICMP que citam o cabeçalho TCP, que o tshark põe no
fluxo mas não são segmentos da conexão.

Cada `<nome>.pcap` vem com:
- `<nome>.tshark.json`: `tshark -T json` com os campos IP e TCP e `tcp.analysis.*` (inclui `ack_rtt`).
- `<nome>.ja4.jsonl`: `ja4 -j` da FoxIO (JA4T), um objeto por fluxo.
- `<nome>.p0f.txt`: as observações `syn` e `syn+ack` do `p0f -r`.

Os IPs públicos da máquina de teste foram trocados por endereços de documentação (`198.51.100.10` e
`2001:db8::10`) com `anon.py`, **antes** de gerar as saídas de referência. Os checksums foram recalculados.

## Como regenerar

```bash
test/golden/collect.sh
test/golden/foxio-windows.sh   # windows-foxio, a partir do pcap da FoxIO
```

O script roda no Mac e usa a vps602 sem aprovação, por ser o servidor de testes. Ele faz o seguinte:
- sobe dois `python3 -m http.server` temporários na porta 7700, um em IPv4 e outro em IPv6;
- captura cada caso com `tcpdump -s0` na eth0, filtrando pelo IP do cliente;
- liga o `tc netem` só durante o caso de retransmissão, com perda apenas na porta de origem 7700, para não
  afetar o ssh;
- gera as três saídas de referência na própria VPS e copia tudo para `pcaps/`.

No fim, mesmo em erro, o script remove os listeners, o netem e os arquivos temporários. A remoção é
conferida e aparece no log: "vps602 limpa: sem listener na 7700 e sem netem".

Pré-requisitos:
- **vps602:** `tshark`, `tcpdump` e `p0f` (apt). O `ja4` da FoxIO fica compilado em `/root/ja4-rust`
  (`cargo build --release -p ja4`, Rust via rustup), num diretório isolado em vez do venv que a task
  sugere, porque a ferramenta atual da FoxIO é em Rust.
- **Mac:** curl, Go, Chrome e Firefox.

As versões usadas estão em `pcaps/VERSIONS.txt`.

## Pcaps da FoxIO

Os pcaps de teste da FoxIO (BSD-3), os mesmos do fingerproxy, já estão no repositório desde a task 011, em
`pkg/fingerprint/internal/pcaptest/testdata/syn/`. Lá também estão a licença, a origem e o gabarito do
`ja4` e do `p0f -r`. Não foram copiados de novo.

## Outros golden

- `tls/`: ClientHellos e h2 decifrado de curl, Go, Chrome e Firefox (task 036).
- `quic/`: primeiro voo QUIC (Initials, CRYPTO, parâmetros de transporte, JA4 `q`, SETTINGS e QPACK do h3) de
  curl, quic-go, Chrome e Firefox (task 050).
