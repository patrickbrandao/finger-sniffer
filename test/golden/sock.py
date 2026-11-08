#!/usr/bin/env python3
"""Clientes TCP especiais para os golden pcaps (macOS).

  sock.py keepalive HOST PORTA  conexão parada ~4,5 s com keepalive TCP a cada 1 s, depois um GET
  sock.py rst HOST PORTA        manda um GET e fecha com SO_LINGER 0 (RST)
"""
import socket
import struct
import sys
import time

mode, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
s = socket.create_connection((host, port), timeout=10)
req = b"GET /small.txt HTTP/1.1\r\nHost: golden\r\nConnection: close\r\n\r\n"
if mode == "keepalive":
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    # macOS: TCP_KEEPALIVE (0x10) é o tempo ocioso; TCP_KEEPINTVL (0x101) o intervalo
    s.setsockopt(socket.IPPROTO_TCP, getattr(socket, "TCP_KEEPALIVE", 0x10), 1)
    s.setsockopt(socket.IPPROTO_TCP, getattr(socket, "TCP_KEEPINTVL", 0x101), 1)
    time.sleep(4.5)
    s.sendall(req)
    while s.recv(65536):
        pass
    s.close()
elif mode == "rst":
    s.sendall(req)
    time.sleep(0.2)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()
else:
    sys.exit("modo desconhecido")
