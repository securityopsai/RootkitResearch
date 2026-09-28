#!/usr/bin/env python3
"""Appliance-like syslog sender for failover drills.

Sends sequence-numbered CEF messages to a forwarder VIP at a fixed rate over
ONE long-lived TCP connection (like a firewall), reconnecting when the
connection breaks, or over UDP. Count what arrived with the KQL in the README
("Acceptance tests") to get exact loss and duplicate numbers per drill.

    python3 seqsender.py --target 10.10.20.21 --rate 500 --count 300000 --run drill1

Standard library only; run it from a host in the same network position as
your real senders.
"""
import argparse
import socket
import sys
import time


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", required=True, help="VIP or load balancer IP")
    ap.add_argument("--port", type=int, default=514)
    ap.add_argument("--proto", choices=("tcp", "udp"), default="tcp")
    ap.add_argument("--rate", type=float, default=200, help="messages per second")
    ap.add_argument("--count", type=int, default=60000)
    ap.add_argument("--run", default=time.strftime("run%Y%m%d%H%M%S"),
                    help="run id, used to filter this drill in KQL")
    args = ap.parse_args()

    host = socket.gethostname()
    interval = 1.0 / args.rate
    sock = None
    reconnects = 0
    start = time.monotonic()

    for seq in range(1, args.count + 1):
        ts = time.strftime("%b %d %H:%M:%S")
        # local4.info (PRI 166). CEF lands in CommonSecurityLog via the CEF DCR.
        line = (f"<166>{ts} {host} CEF:0|HATest|seqsender|1.0|100|failover drill|3|"
                f"cs1Label=run cs1={args.run} cn1Label=seq cn1={seq}\n").encode()
        while True:
            try:
                if args.proto == "udp":
                    if sock is None:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.sendto(line, (args.target, args.port))
                else:
                    if sock is None:
                        sock = socket.create_connection((args.target, args.port), timeout=5)
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    sock.sendall(line)
                break
            except OSError as e:
                reconnects += 1
                print(f"{time.strftime('%H:%M:%S')} seq={seq} send failed ({e}); reconnecting",
                      file=sys.stderr, flush=True)
                if sock is not None:
                    sock.close()
                sock = None
                time.sleep(1)
        # Pace against the start time so reconnect pauses don't lower the average rate.
        delay = start + seq * interval - time.monotonic()
        if delay > 0:
            time.sleep(delay)

    if sock is not None:
        sock.close()
    print(f"run={args.run} sent={args.count} reconnects={reconnects} "
          f"elapsed={time.monotonic() - start:.0f}s", flush=True)


if __name__ == "__main__":
    main()
