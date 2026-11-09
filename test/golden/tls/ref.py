#!/usr/bin/env python3
"""Resumo de referência de um caso do golden TLS/h2 (task 036), gerado na vps602 por collect.sh.

Uso: ref.py <caso>   (lê <caso>.pcap, <caso>.keys, <caso>.tshark.json e <caso>.ja4.jsonl no diretório atual)

Grava <caso>.ref.json e, quando há h2, <caso>.client.h2. Tudo vem das ferramentas de referência, sem código do
projeto: JA3/JA4/JA4_r, SNI e ALPN do tshark e JA4/JA4_r do ja4 (o de referência); SETTINGS, WINDOW_UPDATE, PRIORITY e HEADERS (HPACK decodificado
pelo tshark) por conexão; o Akamai HTTP/2 (S[;]|WU|P[,]|PS[,], técnica do fingerproxy) montado a partir desses
campos do tshark; JA4H do ja4 da FoxIO; os bytes h2 decifrados do cliente pelo "follow,tls,raw" do tshark.
"""
import json
import subprocess
import sys

SERVER_PORT = "7702"
PSEUDO = {":method": "m", ":authority": "a", ":scheme": "s", ":path": "p", ":protocol": "c"}


def walk(o):
    """Percorre o JSON do tshark em ordem, devolvendo cada objeto."""
    if isinstance(o, dict):
        yield o
        for v in o.values():
            yield from walk(v)
    elif isinstance(o, list):
        for v in o:
            yield from walk(v)


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def first(o, key):
    for d in walk(o):
        if key in d:
            return d[key]
    return None


def client_hello(d):
    return {
        "ja3": d.get("tls.handshake.ja3"),
        "ja3_full": d.get("tls.handshake.ja3_full"),
        "ja4": d.get("tls.handshake.ja4"),
        "ja4_r": d.get("tls.handshake.ja4_r"),
        "sni": first(d, "tls.handshake.extensions_server_name"),
        "alpn": as_list(first(d, "tls.handshake.extensions_alpn_str")),
    }


def setting(d):
    sid = int(d["http2.settings.id"])
    val = [v for k, v in d.items() if k.startswith("http2.settings.") and k != "http2.settings.id"]
    return [sid, int(val[0]) if val else None]


def h2_frame(d):
    f = {
        "type": int(d["http2.type"]),
        "flags": d.get("http2.flags"),
        "stream": int(d.get("http2.streamid", 0)),
        "length": int(d.get("http2.length", 0)),
    }
    if f["type"] == 4:
        f["settings"] = [setting(s) for s in as_list(d.get("http2.settings"))]
    if f["type"] == 8:
        f["increment"] = int(d["http2.window_update.window_size_increment"])
    if "http2.stream_dependency" in d or "http2.headers.weight" in d:
        f["priority"] = {
            "exclusive": int(d.get("http2.exclusive", 0)),
            "depends_on": int(d.get("http2.stream_dependency", 0)),
            "weight": int(d.get("http2.headers.weight_real", int(d.get("http2.headers.weight", 0)) + 1)),
        }
    if f["type"] == 1:
        hs = []
        for h in walk(d.get("http2.header", [])):
            if "http2.header.name" in h:
                e = {"name": h["http2.header.name"], "value": h.get("http2.header.value", ""),
                     "repr": h.get("http2.header.repr")}
                if "http2.header.index" in h:
                    e["index"] = int(h["http2.header.index"])
                hs.append(e)
        f["headers"] = hs
    return f


def akamai(frames):
    s = next((f for f in frames if f["type"] == 4 and f["flags"] == "0x00"), None)
    if s is None:
        return None
    wu = next((f for f in frames if f["type"] == 8 and f["stream"] == 0), None)
    pri = [f for f in frames if f["type"] == 2 and "priority" in f]
    hdr = next((f for f in frames if f["type"] == 1), None)
    if hdr is None:
        return None
    return "|".join([
        ";".join("%d:%d" % (k, v) for k, v in s["settings"]),
        str(wu["increment"]) if wu else "00",
        ",".join("%d:%d:%d:%d" % (f["stream"], f["priority"]["exclusive"], f["priority"]["depends_on"],
                                  f["priority"]["weight"]) for f in pri) or "0",
        ",".join(PSEUDO.get(h["name"], h["name"]) for h in hdr["headers"] if h["name"].startswith(":")),
    ])


def follow_client(name, stream):
    """Bytes decifrados do cliente na conexão, pelo follow,tls,raw do tshark.

    O follow escreve os dados do "Node 0" (quem enviou primeiro) sem recuo e os do "Node 1" com tabulação; o
    cliente é o nó cuja porta não é a do servidor.
    """
    out = subprocess.run(["tshark", "-r", name + ".pcap", "-o", "tls.keylog_file:" + name + ".keys", "-q",
                          "-z", "follow,tls,raw,%d" % stream], capture_output=True, text=True, check=True).stdout
    client_indented = False
    data = bytearray()
    for line in out.splitlines():
        if line.startswith("Node 0:"):
            client_indented = line.rstrip().endswith(":" + SERVER_PORT)
            continue
        if not line.strip() or line.startswith("=") or ":" in line:
            continue
        if line.startswith("\t") != client_indented:
            continue
        data += bytes.fromhex(line.strip())
    return bytes(data)


def main():
    name = sys.argv[1]
    pkts = json.load(open(name + ".tshark.json"))
    hellos, conns = [], {}
    for p in pkts:
        lay = p["_source"]["layers"]
        stream = int(lay["tcp"]["tcp.stream"])
        to_server = lay["tcp"]["tcp.dstport"] == SERVER_PORT
        for d in walk(lay.get("tls", {})):
            if d.get("tls.handshake.type") == "1":
                ch = client_hello(d)
                ch["tcp_stream"] = stream
                hellos.append(ch)
        if to_server and "http2" in lay:
            for d in walk(lay["http2"]):
                if "http2.type" in d:
                    conns.setdefault(stream, []).append(h2_frame(d))
    ref = {"case": name, "client_hellos": hellos, "http2": []}
    for stream, frames in sorted(conns.items()):
        ref["http2"].append({"tcp_stream": stream, "akamai": akamai(frames), "frames": frames})
    main_conn = next((c for c in ref["http2"] if c["akamai"]), None)
    ref["akamai"] = main_conn["akamai"] if main_conn else None
    ja4h, tool = [], {}
    try:
        for line in open(name + ".ja4.jsonl"):
            t = json.loads(line)
            tool[int(t["stream"])] = t
            for h in t.get("http", []):
                ja4h.append({"tcp_stream": int(t["stream"]), "ja4h": h.get("ja4h"), "ja4h_r": h.get("ja4h_r")})
    except FileNotFoundError:
        pass
    # JA4 do ja4 da FoxIO ao lado do JA4 do tshark: o tshark 4.4 não descarta GREASE nos algoritmos de
    # assinatura (Chrome), então o valor de referência do JA4 é o do ja4
    for ch in hellos:
        t = tool.get(ch["tcp_stream"], {})
        ch["ja4_tool"] = t.get("ja4")
        ch["ja4_r_tool"] = t.get("ja4_r")
    if hellos:
        ref["ja3"] = hellos[0]["ja3"]
        ref["ja4"] = hellos[0]["ja4_tool"]
    ref["ja4h"] = ja4h[0]["ja4h"] if ja4h else None
    ref["ja4h_all"] = ja4h
    if main_conn:
        data = follow_client(name, main_conn["tcp_stream"])
        ref["client_h2_tcp_stream"] = main_conn["tcp_stream"]
        ref["client_h2_bytes"] = len(data)
        open(name + ".client.h2", "wb").write(data)
    json.dump(ref, open(name + ".ref.json", "w"), indent=1)
    open(name + ".ref.json", "a").write("\n")


if __name__ == "__main__":
    main()
