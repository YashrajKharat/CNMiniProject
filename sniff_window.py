#!/usr/bin/env python3
"""Count inbound traffic on one interface for a fixed time window.

Runs inside a Mininet host namespace (as root) and prints one JSON line.
Pure standard library on a raw AF_PACKET socket, so it is much lighter than
Scapy and copes with attack traffic of a few thousand packets per second.

    python3 sniff_window.py --iface web-eth0 --seconds 4
"""
import argparse
import json
import socket
import struct
import time

PACKET_OUTGOING = 4
ETH_P_ALL = 0x0003


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", required=True)
    ap.add_argument("--seconds", type=float, default=4.0)
    args = ap.parse_args()

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.ntohs(ETH_P_ALL))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.bind((args.iface, 0))
    sock.settimeout(0.2)

    pkts = nbytes = tcp = syn = arp = udp = icmp = 0
    ports_by_src = {}     # src ip -> set of dest ports (SYN packets only)
    syn_by_src = {}       # src ip -> SYN count

    start = time.time()
    end = start + args.seconds
    while time.time() < end:
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        if addr[2] == PACKET_OUTGOING or len(data) < 14:
            continue                      # only count inbound frames
        pkts += 1
        nbytes += len(data)
        ethertype = (data[12] << 8) | data[13]
        if ethertype == 0x0806:
            arp += 1
            continue
        if ethertype != 0x0800 or len(data) < 34:
            continue
        ihl = (data[14] & 0x0F) * 4
        proto = data[23]
        if proto == 6:
            tcp += 1
            off = 14 + ihl
            if len(data) >= off + 14:
                flags = data[off + 13]
                if (flags & 0x02) and not (flags & 0x10):   # SYN, no ACK
                    src = socket.inet_ntoa(data[26:30])
                    dport = struct.unpack("!H", data[off + 2:off + 4])[0]
                    syn += 1
                    syn_by_src[src] = syn_by_src.get(src, 0) + 1
                    ports_by_src.setdefault(src, set()).add(dport)
        elif proto == 17:
            udp += 1
        elif proto == 1:
            icmp += 1

    duration = time.time() - start
    top_src = max(syn_by_src, key=syn_by_src.get) if syn_by_src else ""
    print(json.dumps({
        "duration": round(duration, 3),
        "packets": pkts,
        "bytes": nbytes,
        "tcp": tcp,
        "syn": syn,
        "udp": udp,
        "icmp": icmp,
        "arp": arp,
        "unique_ports_max": max((len(v) for v in ports_by_src.values()),
                                default=0),
        "top_syn_src": top_src,
    }))


if __name__ == "__main__":
    main()
