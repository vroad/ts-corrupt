#!/usr/bin/env python3
"""Inject packet loss, transport errors, or scrambling into MPEG-TS read from
stdin and write the result to stdout.

Packets on the PIDs selected by --pid are eligible. Each eligible packet
starts a corruption burst with the probability specified by --rate. A
corruption burst consists of the number of eligible packets specified by
--burst.

Packets in a corruption burst are either dropped or marked with transport
errors or scrambling.
"""

import argparse
import random
import sys

PKT = 188
SYNC = 0x47


def parse_pid(text):
    return int(text, 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rate", type=float, default=0.001,
                    help="probability per packet of starting a burst")
    ap.add_argument("--burst", type=int, default=1,
                    help="packets affected per burst")
    ap.add_argument("--pid", type=parse_pid, action="append",
                    help="restrict to these PIDs; repeatable, default all")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--tei", action="store_true",
                      help="set transport_error_indicator")
    mode.add_argument("--scramble", action="store_true",
                      help="set transport_scrambling_control to the even key")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--report", type=int, default=100000,
                    help="report to stderr every N packets read")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    pids = set(args.pid) if args.pid else None
    verb = "marked" if args.tei else "scrambled" if args.scramble else "dropped"

    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer

    buf = b""
    synced = False
    read = 0
    hit = 0
    per_pid = {}
    remaining = 0

    while True:
        data = stdin.read(65536)
        if not data:
            break
        buf += data

        if not synced:
            # Accept an offset only when the following packet also starts with a
            # sync byte, otherwise a 0x47 inside a payload can be mistaken for
            # the start of a packet.
            for off in range(len(buf) - PKT):
                if buf[off] == SYNC and buf[off + PKT] == SYNC:
                    buf = buf[off:]
                    synced = True
                    break
            if not synced:
                continue

        out = bytearray()
        while len(buf) >= PKT:
            pkt = buf[:PKT]
            buf = buf[PKT:]

            if pkt[0] != SYNC:
                synced = False
                break

            read += 1
            pid = ((pkt[1] & 0x1F) << 8) | pkt[2]
            eligible = pid != 0x1FFF and (pids is None or pid in pids)

            if remaining == 0 and eligible and rng.random() < args.rate:
                remaining = args.burst

            if remaining > 0 and eligible:
                remaining -= 1
                hit += 1
                per_pid[pid] = per_pid.get(pid, 0) + 1
                if args.tei:
                    pkt = bytearray(pkt)
                    pkt[1] |= 0x80
                    out += pkt
                elif args.scramble:
                    pkt = bytearray(pkt)
                    pkt[3] |= 0x80
                    out += pkt
                # else: dropped entirely
            else:
                out += pkt

            if args.report and read % args.report == 0:
                top = sorted(per_pid.items(), key=lambda kv: -kv[1])[:5]
                print(f"ts-corrupt: read={read} {verb}={hit} "
                      f"top={[(hex(p), n) for p, n in top]}",
                      file=sys.stderr, flush=True)

        try:
            stdout.write(out)
            stdout.flush()
        except BrokenPipeError:
            return

    print(f"ts-corrupt: total read={read} {verb}={hit}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
