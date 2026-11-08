#!/usr/bin/env python3
"""Troca endereços IP de um pcap (libpcap, Ethernet) e recalcula os checksums IPv4/TCP/UDP.

Uso: anon.py entrada.pcap saida.pcap DE=PARA [DE=PARA ...]

Serve para tirar o IP público da máquina de teste dos golden pcaps antes de gerar as saídas de referência.
"""
import ipaddress
import struct
import sys


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def fix_l4(proto, pseudo, seg):
    off = {6: 16, 17: 6}.get(proto)
    if off is None or len(seg) < off + 2:
        return seg
    seg[off:off + 2] = b"\0\0"
    c = csum(pseudo + bytes(seg))
    if proto == 17 and c == 0:
        c = 0xFFFF
    seg[off:off + 2] = struct.pack("!H", c)
    return seg


def rewrite(frame, m):
    if len(frame) < 14:
        return frame
    off = 14
    eth = struct.unpack("!H", frame[12:14])[0]
    if eth == 0x8100 and len(frame) >= 18:
        eth, off = struct.unpack("!H", frame[16:18])[0], 18
    ip = frame[off:]
    if eth == 0x0800 and len(ip) >= 20:
        ihl = (ip[0] & 15) * 4
        for a in (12, 16):
            k = bytes(ip[a:a + 4])
            if k in m:
                ip[a:a + 4] = m[k]
        ip[10:12] = b"\0\0"
        ip[10:12] = struct.pack("!H", csum(bytes(ip[:ihl])))
        tot = struct.unpack("!H", ip[2:4])[0]
        if struct.unpack("!H", ip[6:8])[0] & 0x1FFF == 0 and tot <= len(ip):
            seg = ip[ihl:tot]
            pseudo = bytes(ip[12:20]) + struct.pack("!BBH", 0, ip[9], len(seg))
            ip[ihl:tot] = fix_l4(ip[9], pseudo, seg)
    elif eth == 0x86DD and len(ip) >= 40:
        for a in (8, 24):
            k = bytes(ip[a:a + 16])
            if k in m:
                ip[a:a + 16] = m[k]
        plen = struct.unpack("!H", ip[4:6])[0]
        if 40 + plen <= len(ip):
            seg = ip[40:40 + plen]
            pseudo = bytes(ip[8:40]) + struct.pack("!IxxxB", plen, ip[6])
            ip[40:40 + plen] = fix_l4(ip[6], pseudo, seg)
    frame[off:] = ip
    return frame


def main():
    src, dst, pairs = sys.argv[1], sys.argv[2], sys.argv[3:]
    m = {}
    for p in pairs:
        a, b = p.split("=")
        m[ipaddress.ip_address(a).packed] = ipaddress.ip_address(b).packed
    d = open(src, "rb").read()
    magic = struct.unpack("<I", d[:4])[0]
    if magic not in (0xA1B2C3D4, 0xA1B23C4D):
        sys.exit("anon.py: só pcap libpcap little-endian")
    out = bytearray(d[:24])
    o = 24
    while o + 16 <= len(d):
        ts, us, cl, wl = struct.unpack("<IIII", d[o:o + 16])
        frame = bytearray(d[o + 16:o + 16 + cl])
        o += 16 + cl
        out += struct.pack("<IIII", ts, us, cl, wl) + rewrite(frame, m)
    open(dst, "wb").write(out)


if __name__ == "__main__":
    main()
