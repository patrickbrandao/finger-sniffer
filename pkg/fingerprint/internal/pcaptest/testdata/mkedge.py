#!/usr/bin/env python3
# Gera syn/edge-cases.pcap: SYNs sintéticos com casos de borda de IP e opções TCP, para que os gabaritos
# (ja4 da FoxIO e p0f -r) definam o comportamento esperado. Uso: python3 mkedge.py
import os
import struct

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def tcp(sport, dport, opts, flags=0x02, win=64240, seq=1000, ack=0, urg=0, payload=b'', res=0):
    opts = bytes(opts)
    pad = (-len(opts)) % 4
    opts += b'\0' * pad
    doff = (20 + len(opts)) // 4
    hdr = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (doff << 4) | res, flags, win, 0, urg)
    return hdr + opts + payload

def ip4(src, dst, seg, ttl=64, ident=0x1234, df=True, tos=0, ipopts=b'', mbz=False):
    ihl = 5 + len(ipopts) // 4
    fo = (0x4000 if df else 0) | (0x8000 if mbz else 0)
    h = struct.pack('!BBHHHBBH4s4s', (4 << 4) | ihl, tos, ihl * 4 + len(seg), ident, fo, ttl, 6, 0,
                    bytes(src), bytes(dst)) + ipopts
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    ph = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 6, len(seg))
    seg = seg[:16] + struct.pack('!H', csum(ph + seg[:16] + b'\0\0' + seg[18:])) + seg[18:]
    return b'\x08\x00', h + seg

def ip6(src, dst, seg, hlim=64, flow=0, tc=0):
    h = struct.pack('!IHBB16s16s', (6 << 28) | (tc << 20) | flow, len(seg), 6, hlim, bytes(src), bytes(dst))
    ph = bytes(src) + bytes(dst) + struct.pack('!IxxxB', len(seg), 6)
    seg = seg[:16] + struct.pack('!H', csum(ph + seg[:16] + b'\0\0' + seg[18:])) + seg[18:]
    return b'\x86\xdd', h + seg

C4 = [198, 51, 100, 7]
S4 = [203, 0, 113, 1]
C6 = bytes.fromhex('20010db8000000000000000000000007')
S6 = bytes.fromhex('20010db8000000000000000000000001')
MSS = [2, 4, 0x05, 0xb4]
LINUX = MSS + [4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7]

cases = [
    # sintaxe normal de referência (Linux)
    ip4(C4, S4, tcp(40001, 443, LINUX)),
    # EOL seguido de bytes não nulos
    ip4(C4, S4, tcp(40002, 443, MSS + [0, 1, 3, 3, 7])),
    # MSS com tamanho 3 (inválido) e depois um MSS válido
    ip4(C4, S4, tcp(40003, 443, [2, 3, 5, 1, 2, 4, 0x05, 0x78, 1, 1])),
    # duas opções MSS válidas: vale a última
    ip4(C4, S4, tcp(40004, 443, [2, 4, 0x05, 0xb4, 2, 4, 0x02, 0x18])),
    # opção desconhecida (TFO 34, MD5 19) e SACK (5) no SYN
    ip4(C4, S4, tcp(40005, 443, MSS + [34, 2, 19, 18] + [0] * 16 + [5, 10, 0, 0, 0, 1, 0, 0, 0, 2])),
    # tamanho da opção passa do fim do cabeçalho
    ip4(C4, S4, tcp(40006, 443, MSS + [1, 3, 9, 7])),
    # tamanho de opção 0 e 1 (inválidos)
    ip4(C4, S4, tcp(40007, 443, MSS + [30, 0, 1, 1])),
    ip4(C4, S4, tcp(40008, 443, MSS + [30, 1, 1, 1])),
    # wscale 15 (excessivo) e wscale 0
    ip4(C4, S4, tcp(40009, 443, MSS + [1, 3, 3, 15])),
    ip4(C4, S4, tcp(40010, 443, MSS + [1, 3, 3, 0])),
    # ECN no SYN (ECE+CWR) e TOS/ECN no IP
    ip4(C4, S4, tcp(40011, 443, LINUX, flags=0xC2), tos=0x2a),
    # SYN com dados (TFO)
    ip4(C4, S4, tcp(40012, 443, LINUX, payload=b'GET / HTTP/1.1\r\n\r\n')),
    # opções IP (4 bytes), sem DF e IP ID zero, bit "must be zero"
    ip4(C4, S4, tcp(40013, 443, LINUX), df=False, ident=0, ipopts=b'\x94\x04\x00\x00', mbz=True),
    # ACK não nulo sem a flag ACK, URG ptr sem URG, PSH no SYN, NS
    ip4(C4, S4, tcp(40014, 443, LINUX, ack=0x01020304, urg=7, flags=0x0A, res=1)),
    ip4(C4, S4, tcp(40015, 443, LINUX, ack=0x02000000)),
    # URG no SYN, seq zero
    ip4(C4, S4, tcp(40016, 443, LINUX, flags=0x22, seq=0, urg=1)),
    # timestamps: ts1 zero e ts2 não nulo
    ip4(C4, S4, tcp(40017, 443, MSS + [4, 2, 8, 10, 0, 0, 0, 0, 0, 0, 0, 9, 1, 3, 3, 7])),
    # sem opções, TTL alto (255) e baixo (1)
    ip4(C4, S4, tcp(40018, 443, [], win=1024), ttl=255),
    ip4(C4, S4, tcp(40019, 443, MSS, win=5840), ttl=1),
    # janela múltipla do MSS e do MTU
    ip4(C4, S4, tcp(40020, 443, LINUX, win=1460 * 10)),
    ip4(C4, S4, tcp(40021, 443, LINUX, win=1500 * 4)),
    # IPv6 com flow label e traffic class
    ip6(C6, S6, tcp(40022, 443, [2, 4, 0x05, 0xa0] + LINUX[4:], win=64800), flow=0x12345, tc=0x01),
    ip6(C6, S6, tcp(40023, 443, [2, 4, 0x05, 0xa0] + LINUX[4:], win=1440 * 45), hlim=57),
    # 26 NOPs (mais que MAX_TCP_OPT do p0f)
    ip4(C4, S4, tcp(40024, 443, [1] * 26 + MSS)),
    # SYN+ACK com MSS especial do p0f-sendsyn (1331) e SYN especial (janela 1337)
    ip4(C4, S4, tcp(40025, 443, [2, 4, 0x05, 0x33], win=1337)),
    # opção kind=0 no meio seguida só de zeros
    ip4(C4, S4, tcp(40026, 443, [0, 0, 0, 0] + MSS)),
    # MSS sozinho com tamanho 3, WS com tamanho 4, MSS com tamanho 2 e MSS com tamanho 5
    ip4(C4, S4, tcp(40027, 443, [2, 3, 5, 1])),
    ip4(C4, S4, tcp(40028, 443, [3, 4, 7, 0])),
    ip4(C4, S4, tcp(40029, 443, [2, 2, 1, 1])),
    ip4(C4, S4, tcp(40030, 443, [2, 5, 5, 0xb4, 9, 1, 1, 1])),
    # EOL, zero e depois byte não nulo
    ip4(C4, S4, tcp(40031, 443, [3, 3, 7, 0, 0, 1, 1, 1])),
    # cabeçalho TCP com doff maior que o segmento (truncado)
    ip4(C4, S4, tcp(40032, 443, MSS)[:22]),
]

out = bytearray(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
t = 1700000000
for i, (et, pkt) in enumerate(cases):
    frame = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + et + pkt
    out += struct.pack('<IIII', t + i, 0, len(frame), len(frame)) + frame
path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'syn', 'edge-cases.pcap')
with open(path, 'wb') as f:
    f.write(out)
