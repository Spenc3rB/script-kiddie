"""
Dump / send J1708 (SAE J1587) frames with an RP1210 adapter (DPA/DPA XL, Nexiq, etc.).

Key points
----------
* **Max J1708 frame length is 21 bytes TOTAL** (MID + data + checksum). This tool will let you send
  anything up to that limit.
* If you pass `--auto-cs`, the tool will append the two's-complement checksum for you. Otherwise it
  assumes you've already included it.
* The previous version only auto-added CS when exactly 4 bytes were given—hence the apparent "limit".
  That's now fixed.
* RP1210 DLLs are 32-bit. Use 32-bit Python ( `struct.calcsize("P")*8 == 32` ).
* dfieschko/rp1210 clamps `setBlockingTimeout()` params to 0-255 ms. We clamp for you.

Examples
--------
# List installed APIs / devices / protocols
python j1708dump.py --list

# Sniff everything
python j1708dump.py --api DGDPA5 --device 1 --protocol J1708

# Filter on MID 0x88 and PID 0x9E, print checksum separately
python j1708dump.py --api DGDPA5 --device 1 --protocol J1708 --filter-mid 0x88 --filter-pid 0x9e --show-cs

# Send a 5-byte full frame (checksum already included)
python j1708dump.py --api DGDPA5 --device 1 --protocol J1708 --send 88 9e 88 13 3f

# Send a 4-byte payload and have the tool append checksum (total 5 bytes on wire)
python j1708dump.py --api DGDPA5 --device 1 --protocol J1708 --send 88 9e 88 13 --auto-cs

# Blast a long (<=21B) frame every 200 ms, 10 times, and log to file
python j1708dump.py --api DGDPA5 --device 1 --protocol J1708 \
  --send 88 c0 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 --auto-cs \
  --send-repeat 10 --send-interval 0.2 --log out.hex
"""
# Copyright (c) 2025, Spenc3rB

import argparse
import sys
import time
from typing import Iterable, Optional, List

try:
    from RP1210 import RP1210Client, translateErrorCode
except ImportError:
    print("[-] Could not import RP1210. Install with: pip install rp1210", file=sys.stderr)
    raise

MAX_J1708_LEN = 21  # MID..CS

# ------------------- Helpers -------------------

def checksum(buf: bytes) -> int:
    """Two's complement checksum for J1708/J1587."""
    return ((~sum(buf)) + 1) & 0xFF

def parse_int_list(text: Optional[str]) -> Optional[List[int]]:
    if not text:
        return None
    parts = [p.strip() for p in text.replace(',', ' ').split() if p.strip()]
    return [int(p, 0) for p in parts]

def hexdump_line(b: bytes, show_cs: bool = False) -> str:
    if not show_cs or len(b) < 2:
        return b.hex(' ')
    return f"{b[:-1].hex(' ')} | cs={b[-1]:02x}"

def pick_vendor(client: RP1210Client, api_name: str):
    """Return the RP1210Config vendor object matching api_name (case-insensitive)."""
    for v in client.getVendorList():
        get_api = getattr(v, 'getAPIName', None)
        api = get_api() if callable(get_api) else getattr(v, 'APIName', getattr(v, 'api', None))
        if api and api.lower() == api_name.lower():
            return v
    raise SystemExit(f"API '{api_name}' not found. Use --list to see available APIs.")

# ------------------- Core -------------------

def list_things():
    c = RP1210Client()
    vendors = c.getVendorList()
    if not vendors:
        print("No RP1210 vendors found. Are drivers installed?", file=sys.stderr)
        return
    for v in vendors:
        api = getattr(v, 'getAPIName', None)
        api = api() if callable(api) else getattr(v, 'APIName', getattr(v, 'api', '???'))
        name = getattr(v, 'getName', None)
        name = name() if callable(name) else getattr(v, 'name', 'unknown')
        devs = getattr(v, 'getDeviceIDs', lambda: [])()
        prots = getattr(v, 'getProtocolNames', lambda: [])()
        print(f"API: {api}  ({name})")
        print(f"  Devices  : {devs}")
        print(f"  Protocols: {prots}\n")


def connect(api: str, device_id: int, protocol: str) -> RP1210Client:
    c = RP1210Client()
    pick_vendor(c, api)  # just to validate
    c.setVendor(api)
    c.setDevice(device_id)

    rc = c.connect(protocol.encode('ascii'))
    if rc != 0:
        print(f"connect rc={rc} -> {translateErrorCode(rc)}", file=sys.stderr)
        sys.exit(1)

    c.setAllFiltersToPass()
    return c

def set_blocking_timeout(c: RP1210Client, timeout_ms: int):
    # dfieschko/rp1210 uses 1-byte values for this command
    t = max(0, min(timeout_ms, 255))
    c.setBlockingTimeout(t, 1)


def rx_frame(c: RP1210Client, bufsize: int = 8192) -> Optional[bytes]:
    data = c.rx(buffer_size=bufsize, blocking=1)
    if not data:
        return None
    return data[4:]  # strip RP1210 4-byte header


def matches_filters(msg: bytes, mids: Optional[List[int]], pids: Optional[List[int]]) -> bool:
    if len(msg) < 2:
        return False
    if mids is not None and msg[0] not in mids:
        return False
    if pids is not None and msg[1] not in pids:
        return False
    return True

# ------------------- Args -------------------

def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Dump/send J1708/J1587 frames over RP1210")
    p.add_argument('--list', action='store_true', help='List APIs/devices/protocols and exit')

    p.add_argument('--api', '--vendor', dest='api', help='RP1210 API name (e.g. DGDPA5, DGDPAXL, NULN2R32)')
    p.add_argument('--device', type=int, default=1, help='Device ID (default: 1)')
    p.add_argument('--protocol', default='J1708', help='Protocol string per driver (default: J1708)')

    p.add_argument('--timeout', type=float, default=0.2, help='Per-read timeout seconds (<=0.255 recommended)')
    p.add_argument('--duration', type=float, default=None, help='Stop after N seconds')
    p.add_argument('--count', type=int, default=None, help='Stop after N frames')

    p.add_argument('--filter-mid', dest='filter_mid', help='Comma/space list of MIDs (e.g. 0x88 0x80)')
    p.add_argument('--filter-pid', dest='filter_pid', help='Comma/space list of PIDs (e.g. 0x9e 158)')

    p.add_argument('--show-cs', action='store_true', help='Print last byte separately as checksum')

    p.add_argument('--checksum', action='store_true', help='Ask driver to include checksum on read (depends on wrapper)')
    p.add_argument('--echo', action='store_true', help='Request echo of transmitted frames (if supported)')
    p.add_argument('--log', help='Write received frames (hex) to this file')

    # Sending
    p.add_argument('--send', nargs='+', help='Bytes to TX (hex or dec). Max 21 bytes including checksum.')
    p.add_argument('--auto-cs', action='store_true', help='Append checksum for you (if you did not include it)')
    p.add_argument('--send-interval', type=float, default=0.5, help='Interval between repeated sends in seconds')
    p.add_argument('--send-repeat', type=int, default=1, help='Times to send the frame')

    return p.parse_args(argv)


def build_send_bytes(args) -> Optional[bytes]:
    if not args.send:
        return None
    vals = [int(x, 0) for x in args.send]
    if len(vals) > MAX_J1708_LEN:
        raise SystemExit(f"Too many bytes ({len(vals)}). Max J1708 length is {MAX_J1708_LEN} (including CS).")

    if args.auto_cs:
        # If user already supplied a full-length with CS, verify and keep
        if len(vals) >= 2 and len(vals) <= MAX_J1708_LEN:
            cs_needed = checksum(bytes(vals[:-1]))
            if len(vals) >= 3 and vals[-1] == cs_needed:
                # Already correct
                return bytes(vals)
            # else append CS
            if len(vals) == MAX_J1708_LEN:
                raise SystemExit("No room to append checksum; drop one byte or include CS yourself.")
            vals.append(checksum(bytes(vals)))
    return bytes(vals)

# ------------------- Main -------------------

def main(argv=None):
    args = parse_args(argv)

    if args.list:
        list_things()
        return 0

    if not args.api:
        print('--api is required unless using --list', file=sys.stderr)
        return 1

    client = connect(args.api, args.device, args.protocol)

    if args.echo:
        try:
            client.setEchoTransmit(1)
        except Exception:
            pass

    set_blocking_timeout(client, int(args.timeout * 1000))

    send_bytes = build_send_bytes(args)
    if send_bytes:
        print(f"[TX] {send_bytes.hex(' ')}")
        if len(send_bytes) > MAX_J1708_LEN:
            raise SystemExit(f"Send frame too long ({len(send_bytes)} > {MAX_J1708_LEN})")
        for _ in range(args.send_repeat):
            # RP1210 wants a leading type byte; dfieschko wrapper will accept raw, but we mimic hv_networks style
            client.tx(bytearray([0]) + send_bytes)
            time.sleep(args.send_interval)

    mids = parse_int_list(args.filter_mid)
    pids = parse_int_list(args.filter_pid)

    logfh = open(args.log, 'w') if args.log else None

    start = time.time()
    seen = 0
    try:
        while True:
            if args.duration and (time.time() - start) >= args.duration:
                break
            if args.count and seen >= args.count:
                break

            msg = rx_frame(client)
            if msg is None:
                continue

            if not matches_filters(msg, mids, pids):
                continue

            seen += 1
            line = hexdump_line(msg, show_cs=args.show_cs)
            api_name = args.api
            mid = msg[0] if len(msg) > 0 else 0
            pid = msg[1] if len(msg) > 1 else 0
            data_bytes = msg[2:] if len(msg) > 2 else b''
            line = f"{api_name}  {mid:02X} {pid:02X}  [{len(data_bytes)}]  {data_bytes.hex(' ')}"
            print(line)
            if logfh:
                logfh.write(line + '\n')
                logfh.flush()

    except KeyboardInterrupt:
        pass
    finally:
        if logfh:
            logfh.close()
        try:
            client.disconnect()
        except Exception:
            pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
