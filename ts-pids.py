#!/usr/bin/env python3
"""Print ts-corrupt.py --pid arguments for the PIDs of a packet category.

Categories follow how mirakc-arib's `record-service --packet-stats` classifies
packets: video, audio, subtitle and pmt correspond to the droppedPackets fields
of the same name, and `other` covers the remaining PIDs that the PMT lists,
such as a PCR-only PID.  The classification here relies on stream_type and
component_tag, which is enough for ARIB streams.

PMT parsing is delegated to TSDuck.
"""

import argparse
import json
import shutil
import subprocess
import sys

# stream_type values accepted by tsduck's IsVideoST()/IsAudioST().
VIDEO_TYPES = {0x01, 0x02, 0x10, 0x1B, 0x24, 0x25}
AUDIO_TYPES = {0x03, 0x04, 0x0F, 0x11, 0x81, 0x87}
# ARIB component_tag ranges: 0x30-0x37 subtitle, 0x38-0x3F superimposed text.
SUBTITLE_TAGS = range(0x30, 0x40)

CATEGORIES = ("video", "audio", "subtitle", "pmt", "other")
NULL_PID = 0x1FFF


def die(msg):
    sys.exit(f"{sys.argv[0].split('/')[-1]}: {msg}")


def component_tag(stream):
    for node in stream.get("#nodes", []):
        if "component_tag" in node:
            return node["component_tag"]
    return None


def classify(stream):
    if component_tag(stream) in SUBTITLE_TAGS:
        return "subtitle"
    stream_type = stream.get("stream_type")
    if stream_type in VIDEO_TYPES:
        return "video"
    if stream_type in AUDIO_TYPES:
        return "audio"
    return "other"


def read_tables(args):
    """Run <source> | tsresync | tstables and return the parsed JSON tables."""
    # tstables detects the packet format only from an input that starts on a
    # packet boundary.  A live capture can start mid-packet, so we run tsresync
    # first.
    if args.url:
        source = subprocess.Popen(
            ["curl", "-sN", "-m", str(args.seconds), args.url],
            stdout=subprocess.PIPE)
        stdin = source.stdout
    elif args.file == "-":
        stdin = sys.stdin.buffer
    else:
        stdin = open(args.file, "rb")

    resync = subprocess.Popen(["tsresync"], stdin=stdin,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    tables = subprocess.Popen(
        ["tstables", "--tid", "2", "--max-tables", "8", "--json-output", "-"],
        stdin=resync.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    resync.stdout.close()
    out = tables.communicate()[0]

    # We ignore the exit codes: curl exits non-zero when --max-time fires, and
    # that is how a live capture normally ends.  Empty output is the only
    # failure we detect.
    if not out.strip():
        die("no PMT found in the stream")
    return json.loads(out)


def collect(tables, sid):
    pmts = [t for t in tables if t.get("#name") == "PMT"]
    if not pmts:
        die("no PMT found in the stream")
    if sid is None:
        pmt = pmts[0]
    else:
        pmt = next((t for t in pmts if t.get("service_id") == sid), None)
        if pmt is None:
            found = ", ".join(str(t.get("service_id")) for t in pmts)
            die(f"sid {sid} not found; PMTs in the stream: {found}")

    found = {}
    for node in pmt.get("#nodes", []):
        if "elementary_pid" in node:
            found.setdefault(node["elementary_pid"], classify(node))
        elif node.get("#name") == "metadata":
            found.setdefault(node["pid"], "pmt")
    if pmt.get("pcr_pid") is not None:
        found.setdefault(pmt["pcr_pid"], "other")
    found.pop(NULL_PID, None)
    return found


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-c", "--category", action="append", required=True,
                    help=f"repeatable or comma-separated: {' '.join(CATEGORIES)}")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("-u", "--url", help="capture from an HTTP stream")
    src.add_argument("-f", "--file", help="read a TS file ('-' for stdin)")
    ap.add_argument("-s", "--sid", type=int,
                    help="service ID; defaults to the first PMT found")
    ap.add_argument("-t", "--seconds", type=int, default=8,
                    help="capture duration for --url (default: 8)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="print the resolved PID table to stderr")
    args = ap.parse_args()

    wanted = [c for arg in args.category for c in arg.split(",") if c]
    for category in wanted:
        if category == "pat":
            die("pat is not supported: droppedPackets has no pat field, "
                "because ServiceFilter regenerates PAT")
        if category not in CATEGORIES:
            die(f"unknown category: {category}")

    for tool in ("tsresync", "tstables"):
        if not shutil.which(tool):
            die(f"{tool} not found; try: nix shell nixpkgs#tsduck")

    found = collect(read_tables(args), args.sid)
    pids = sorted(pid for pid, category in found.items() if category in wanted)
    if not pids:
        die("no PID matched; check --sid and --category")

    if args.verbose:
        for pid in pids:
            print(f"pid=0x{pid:04X} ({pid})\t{found[pid]}", file=sys.stderr)

    print(" ".join(f"--pid {pid}" for pid in pids))


if __name__ == "__main__":
    main()
