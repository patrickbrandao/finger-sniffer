#!/usr/bin/env python3
"""Resumo de referência de um caso do golden QUIC (task 050), gerado na vps602 por collect.sh.

Uso: ref.py <caso> [descrição do cliente]
     (lê <caso>.pcap, <caso>.keys, <caso>.tshark.json e <caso>.ja4.jsonl no diretório atual)

Grava <caso>.ref.json. Tudo vem das ferramentas de referência (tshark 4.4 e ja4 da FoxIO), sem código do
projeto. Por conexão QUIC do cliente (um fluxo UDP):
  - os datagramas do cliente com pacote Initial até o que completa o ClientHello (client_hello_datagrams), cada
    um com tamanho, pacotes coalescidos (tipo, versão, DCID/SCID, token, Length, número) e frames na ordem;
  - os frames CRYPTO na ordem de chegada, se vieram fora de ordem ou sobrepostos;
  - o ClientHello dissecado pelo tshark (JA3, JA4, SNI, ALPN, extensões na ordem) e os parâmetros de transporte
    na ordem, [id, nome do tshark, valor em hex];
  - JA4, JA4_r e JA4S do ja4 da FoxIO (o JA4 de referência);
  - o primeiro voo do servidor (datagramas com Initial);
  - com as chaves: SETTINGS do h3 de cada lado e os HEADERS do cliente (bloco QPACK cru e campos decodificados).
Os nomes dos frames QUIC são os da RFC 9000 seção 19 (tabela abaixo); os tipos vêm do tshark.
"""
import json
import subprocess
import sys

SERVER_PORT = "7703"

FRAME_NAMES = {
    0x00: "PADDING", 0x01: "PING", 0x02: "ACK", 0x03: "ACK_ECN", 0x04: "RESET_STREAM", 0x05: "STOP_SENDING",
    0x06: "CRYPTO", 0x07: "NEW_TOKEN", 0x10: "MAX_DATA", 0x11: "MAX_STREAM_DATA", 0x12: "MAX_STREAMS_BIDI",
    0x13: "MAX_STREAMS_UNI", 0x14: "DATA_BLOCKED", 0x15: "STREAM_DATA_BLOCKED", 0x16: "STREAMS_BLOCKED_BIDI",
    0x17: "STREAMS_BLOCKED_UNI", 0x18: "NEW_CONNECTION_ID", 0x19: "RETIRE_CONNECTION_ID", 0x1A: "PATH_CHALLENGE",
    0x1B: "PATH_RESPONSE", 0x1C: "CONNECTION_CLOSE", 0x1D: "CONNECTION_CLOSE_APP", 0x1E: "HANDSHAKE_DONE",
}
for _t in range(0x08, 0x10):
    FRAME_NAMES[_t] = "STREAM"
PACKET_TYPES = {0: "initial", 1: "0rtt", 2: "handshake", 3: "retry"}


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def hexs(v):
    return (v or "").replace(":", "")


def num(v):
    return int(v, 0) if isinstance(v, str) and v else None


def quic_frame(f):
    t = num(f.get("quic.frame_type"))
    out = {"type": t, "name": FRAME_NAMES.get(t, "unknown")}
    if t == 0x00:
        out["length"] = num(f.get("quic.padding_length"))
    elif t == 0x06:
        out["offset"] = num(f.get("quic.crypto.offset"))
        out["length"] = num(f.get("quic.crypto.length"))
    elif t in (0x02, 0x03):
        out["largest_acknowledged"] = num(f.get("quic.ack.largest_acknowledged"))
        out["ack_range_count"] = num(f.get("quic.ack.ack_range_count"))
    elif t in (0x1C, 0x1D):
        out["error_code"] = num(f.get("quic.cc.error_code") or f.get("quic.cc.error_code.app"))
    return out


def quic_packet(q):
    if "quic.header_form" not in q:
        # bytes aleatórios depois do último pacote (o Firefox completa o datagrama assim, RFC 9000 12.2)
        return {"type": "coalesced_padding"}
    if "quic.long.packet_type" not in q:
        # cabeçalho curto (1-RTT): só o tamanho, o conteúdo fica fora do primeiro voo
        return {"type": "1rtt", "packet_length": num(q.get("quic.packet_length"))}
    pt = num(q["quic.long.packet_type"])
    return {
        "type": PACKET_TYPES.get(pt, str(pt)),
        "version": q.get("quic.version"),
        "dcid": hexs(q.get("quic.dcid")),
        "scid": hexs(q.get("quic.scid")),
        "token_length": num(q.get("quic.token_length")),
        "length": num(q.get("quic.length")),
        "packet_number": num(q.get("quic.packet_number")),
        "packet_length": num(q.get("quic.packet_length")),
        "frames": [quic_frame(f) for f in as_list(q.get("quic.frame"))],
    }


def datagram(layers):
    udp = layers["udp"]
    return {
        "frame": num(layers["frame"]["frame.number"]),
        "time_relative": layers["frame"].get("frame.time_relative"),
        "udp_payload_length": num(udp["udp.length"]) - 8,
        "packets": [quic_packet(q) for q in as_list(layers.get("quic"))],
    }


def has_initial(dg):
    return any(p["type"] == "initial" for p in dg["packets"])


def ordered_pairs(pairs):
    # mantém chaves duplicadas e a ordem: o tshark repete "Parameter: GREASE" quando há mais de um
    return pairs


def find_pairs(node, key):
    """Procura recursivamente, em ordem, valores cuja chave começa com key num JSON lido como lista de pares."""
    if isinstance(node, list):
        if node and all(isinstance(x, tuple) and len(x) == 2 for x in node):
            for k, v in node:
                if k.startswith(key):
                    yield k, v
                yield from find_pairs(v, key)
        else:
            for x in node:
                yield from find_pairs(x, key)


def get(pairs, key):
    for k, v in pairs if isinstance(pairs, list) else []:
        if k == key:
            return v
    return None


def client_hellos(case):
    """ClientHellos do cliente com a ordem exata dos parâmetros de transporte, por número de frame."""
    out = subprocess.run(
        ["tshark", "-r", case + ".pcap", "-T", "json", "-J", "frame quic tls",
         "-Y", "tls.handshake.type == 1 && udp.dstport == " + SERVER_PORT],
        check=True, capture_output=True, text=True).stdout
    res = {}
    for pkt in json.loads(out, object_pairs_hook=ordered_pairs):
        frame = None
        for _, v in find_pairs(pkt, "frame.number"):
            frame = int(v)
        for _, hs in find_pairs(pkt, "tls.handshake"):
            if not isinstance(hs, list) or get(hs, "tls.handshake.type") != "1":
                continue
            exts, tps = [], []
            for k, e in hs:
                if not k.startswith("tls.handshake.extension") or not isinstance(e, list):
                    continue
                et = num(get(e, "tls.handshake.extension.type"))
                exts.append(et)
                if et != 57:
                    continue
                for pk, p in e:
                    if pk.startswith("Parameter: ") and isinstance(p, list):
                        name = pk[len("Parameter: "):].split(" (len=")[0]
                        tps.append([num(get(p, "tls.quic.parameter.type")), name,
                                    hexs(get(p, "tls.quic.parameter.value"))])
            sni = [v for k, v in find_pairs(hs, "tls.handshake.extensions_server_name")
                   if k == "tls.handshake.extensions_server_name"]
            alpn = [v for k, v in find_pairs(hs, "tls.handshake.extensions_alpn_str")
                    if k == "tls.handshake.extensions_alpn_str"]
            res[frame] = {
                "handshake_length": num(get(hs, "tls.handshake.length")),
                "ja3": get(hs, "tls.handshake.ja3"),
                "ja3_full": get(hs, "tls.handshake.ja3_full"),
                "ja4_tshark": get(hs, "tls.handshake.ja4"),
                "ja4_r_tshark": get(hs, "tls.handshake.ja4_r"),
                "sni": sni[0] if sni else None,
                "alpn": alpn,
                "extensions": exts,
                "transport_parameters": tps,
            }
    return res


def h3_items(layers):
    """Streams h3 decifrados de um datagrama: SETTINGS (stream de controle) e HEADERS (requisição/resposta)."""
    settings, headers = [], []
    for h in as_list(layers.get("http3")):
        for kind in ("http3.stream.uni", "http3.stream"):
            for s in as_list(h.get(kind)):
                for fr in as_list(s.get("http3.frame")):
                    ft = num(fr.get("http3.frame_type"))
                    if ft == 0x04:
                        settings.append([[num(x.get("http3.settings.id")), num(x.get("http3.settings.value"))]
                                         for x in as_list(fr.get("http3.settings"))])
                    elif ft == 0x01:
                        fields = [[x.get("http3.header.header.name"), x.get("http3.headers.header.value")]
                                  for x in as_list(fr.get("http3.headers.header"))]
                        headers.append({"qpack_block": hexs(fr.get("http3.frame_payload")), "fields": fields})
    return settings, headers


def main():
    case = sys.argv[1]
    client = sys.argv[2] if len(sys.argv) > 2 else ""
    pkts = json.load(open(case + ".tshark.json"))
    tool = [json.loads(line) for line in open(case + ".ja4.jsonl") if line.strip()]
    chs = client_hellos(case)

    conns = {}
    for p in pkts:
        layers = p["_source"]["layers"]
        udp = layers["udp"]
        stream = num(udp["udp.stream"])
        to_server = udp["udp.dstport"] == SERVER_PORT
        c = conns.setdefault(stream, {
            "udp_stream": stream, "client_port": num(udp["udp.dstport" if not to_server else "udp.srcport"]),
            "client_initial_datagrams": [], "server_initial_datagrams": [], "client_hello": None,
            "h3": {"client_settings": [], "server_settings": [], "client_headers": []}, "_done": False,
        })
        dg = datagram(layers)
        if to_server and not c["_done"] and has_initial(dg):
            c["client_initial_datagrams"].append(dg)
            frame = dg["frame"]
            if frame in chs:
                c["client_hello"] = chs[frame]
                c["_done"] = True
        elif not to_server and has_initial(dg):
            c["server_initial_datagrams"].append(dg)
        st, hd = h3_items(layers)
        if to_server:
            c["h3"]["client_settings"] += st
            c["h3"]["client_headers"] += hd
        else:
            c["h3"]["server_settings"] += st

    out = []
    for stream in sorted(conns):
        c = conns.pop(stream)
        c.pop("_done")
        if not c["client_hello"]:
            continue
        crypto = [[f["offset"], f["length"]] for dg in c["client_initial_datagrams"] for pk in dg["packets"]
                  if pk["type"] == "initial" for f in pk["frames"] if f["name"] == "CRYPTO"]
        out_of_order, overlap, end, seen = False, False, 0, []
        for off, ln in crypto:
            if off < end:
                out_of_order = True
            end = max(end, off + ln)
            if any(off < e and s < off + ln for s, e in seen):
                overlap = True
            seen.append((off, off + ln))
        first = c["client_initial_datagrams"][0]["packets"][0]
        t = [x for x in tool if x.get("src_port") == c["client_port"] and x.get("transport") == "udp"]
        t = t[0] if t else {}
        out.append({
            "udp_stream": c["udp_stream"],
            "client_port": c["client_port"],
            "version": first["version"],
            "dcid": first["dcid"],
            "scid": first["scid"],
            "token_length": first["token_length"],
            "client_hello_datagrams": len(c["client_initial_datagrams"]),
            "datagram_sizes": [dg["udp_payload_length"] for dg in c["client_initial_datagrams"]],
            "crypto_frames": crypto,
            "crypto_out_of_order": out_of_order,
            "crypto_overlap": overlap,
            "crypto_length": end,
            "client_hello": {k: v for k, v in c["client_hello"].items() if k != "transport_parameters"},
            "transport_parameters": c["client_hello"]["transport_parameters"],
            "ja4_tool": t.get("ja4"),
            "ja4_r_tool": t.get("ja4_r"),
            "ja4s_tool": t.get("ja4s"),
            "client_initial_datagrams": c["client_initial_datagrams"],
            "server_initial_datagrams": c["server_initial_datagrams"],
            "http3": c["h3"],
        })
    ref = {"case": case, "client": client, "connections": out}
    with open(case + ".ref.json", "w") as f:
        json.dump(ref, f, indent=1, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main()
