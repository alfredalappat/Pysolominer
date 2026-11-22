#!/usr/bin/env python3
"""
pysolominer - a single-threaded, dependency-free solo Bitcoin miner (Stratum v1).

* Detects a lost pool connection (and so a lost internet) and reconnects by itself
* Live statistics dashboard in the terminal
* log.txt is created if missing and wiped (restarted from the top) at 5 MB

Usage:
    python pysolominer.py --address <YOUR_BTC_ADDRESS> --url <POOL_HOST:PORT>
    python pysolominer.py --address <ADDR> --worker rig1 --url <POOL_HOST:PORT>
    python pysolominer.py --selftest
"""

import argparse
import hashlib
import json
import os
import re
import select
import socket
import struct
import sys
import time
from collections import deque
from datetime import datetime

VERSION = "1.0.0"
DIFF1 = 0xFFFF * 2 ** 208          # difficulty-1 target
LOG_MAX_BYTES = 5 * 1024 * 1024    # 5 MB
IDLE_TIMEOUT = 180                 # seconds without any pool data => connection considered lost
RECONNECT_DELAY = 3                # seconds between reconnect attempts
CHUNK = 25000                      # nonces hashed between socket/UI checks
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "log.txt")   # always next to this script

PACK_NONCE = struct.Struct("<I").pack
ZERO2 = b"\x00\x00"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
class FatalError(Exception):
    """Unrecoverable error (e.g. pool refused the worker)."""


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def nonce_hex(n):
    """Stratum sends/receives numeric fields (version, ntime, nbits, nonce) as big-endian hex."""
    return "%08x" % n


def build_prefix(job, en1, en2b):
    """First 76 bytes of the block header for a stratum job (everything except the nonce)."""
    root = dsha(job.c1 + en1 + en2b + job.c2)
    for b in job.branch:
        root = dsha(root + b)
    return job.ver + job.prev + root + job.ntime_b + job.nbits_b


def nbits_to_target(nbits):
    exp = nbits >> 24
    man = nbits & 0xFFFFFF
    return man << (8 * (exp - 3)) if exp > 3 else man >> (8 * (3 - exp))


def fmt_rate(h):
    for unit, div in (("GH/s", 1e9), ("MH/s", 1e6), ("kH/s", 1e3)):
        if h >= div:
            return "%.2f %s" % (h / div, unit)
    return "%.1f H/s" % h


def fmt_diff(d):
    if d is None:
        return "-"
    for unit, div in (("P", 1e15), ("T", 1e12), ("G", 1e9), ("M", 1e6), ("K", 1e3)):
        if d >= div:
            return "%.2f %s" % (d / div, unit)
    if d >= 1:
        return "%.3f" % d
    return "%.6f" % d


def fmt_dur(s):
    s = int(s)
    if s >= 365 * 86400:
        return "%.1f years" % (s / (365.25 * 86400))
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    if d:
        return "%dd %02dh %02dm %02ds" % (d, h, m, s)
    return "%02dh %02dm %02ds" % (h, m, s)


def fmt_int(n):
    return "{:,}".format(int(n))


# --------------------------------------------------------------------------- #
# logger: log.txt, auto-create, 5 MB cap (wipe and start from top)
# --------------------------------------------------------------------------- #
GREEN, RED, RESET = "\033[92m", "\033[91m", "\033[0m"     # the only colours used


class Logger:
    """Writes every event to log.txt and (unless show=False) as a new row on screen."""

    def __init__(self, path):
        self.path = path
        existed = os.path.exists(path)
        self._ensure()
        self.write("INFO", "Log file %s" % ("found" if existed else "was missing - created new one"))

    def _ensure(self):
        try:
            if not os.path.exists(self.path):
                open(self.path, "a", encoding="utf-8").close()
        except OSError:
            pass

    def size(self):
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    def write(self, level, msg, show=True):
        now = datetime.now()
        stamp = now.strftime("%Y-%m-%d %H:%M:%S")
        line = "[%s] [%-5s] %s\n" % (stamp, level, msg)
        try:
            mode = "a"
            if self.size() >= LOG_MAX_BYTES:
                mode = "w"                  # wipe, start from the top
                line = ("[%s] [INFO ] log.txt reached 5 MB - cleaned, starting from top\n" % stamp) + line
            with open(self.path, mode, encoding="utf-8") as f:   # 'a' re-creates if deleted
                f.write(line)
        except OSError:
            pass
        if show:
            low = msg.lower()
            if level in ("LOST", "FATAL") or "rejected" in low:
                color = RED
            elif level == "FOUND" or "accepted" in low or "reconnected" in low or low.startswith("connected to"):
                color = GREEN
            else:
                color = ""
            out = "%s  %-6s %s" % (now.strftime("%H:%M:%S"), level, msg)
            print(color + out + RESET if color else out, flush=True)


# --------------------------------------------------------------------------- #
# job
# --------------------------------------------------------------------------- #
class Job:
    def __init__(self, p):
        (self.id, prev, c1, c2, branch, ver, nbits, ntime, self.clean) = p[:9]
        prev_b = bytes.fromhex(prev)
        self.prev = b"".join(prev_b[i:i + 4][::-1] for i in range(0, 32, 4))
        self.c1 = bytes.fromhex(c1)
        self.c2 = bytes.fromhex(c2)
        self.branch = [bytes.fromhex(x) for x in branch]
        self.ver = bytes.fromhex(ver)[::-1]
        self.nbits_b = bytes.fromhex(nbits)[::-1]
        self.ntime_hex = ntime
        self.ntime_b = bytes.fromhex(ntime)[::-1]
        self.net_target = nbits_to_target(int(nbits, 16))
        self.net_diff = DIFF1 / self.net_target if self.net_target else 0
        self.height = self._height()
        self.received = time.time()

    def _height(self):
        # BIP34: block height is the first push in the coinbase scriptSig
        try:
            n = self.c1[42]
            if 1 <= n <= 4:
                h = int.from_bytes(self.c1[43:43 + n], "little")
                if 0 < h < 10_000_000:
                    return h
        except IndexError:
            pass
        return None


# --------------------------------------------------------------------------- #
# miner
# --------------------------------------------------------------------------- #
class Miner:
    def __init__(self, host, port, user, password, log, refresh=30.0):
        self.host, self.port = host, port
        self.user, self.password = user, password
        self.log = log
        self.refresh = refresh

        self.sock = None
        self.buf = b""
        self.last_rx = time.time()
        self.status = "CONNECTING"
        self.lost_since = None
        self.lost_reason = ""
        self.lost_announced = False

        self.en1 = None
        self.en2_size = 4
        self.job = None
        self.job_seq = 0
        self.pool_diff = 1.0
        self.share_target = int(DIFF1 / self.pool_diff)

        self.sid = 100
        self.pending = {}

        self.start = time.time()
        self.hashes = 0
        self.accepted = 0
        self.rejected = 0
        self.accepted_diff = 0.0
        self.best_diff = 0.0
        self.blocks_found = 0
        self.reconnects = 0
        self.last_share = "-"
        self.last_draw = time.time()
        self.last_snapshot = time.time()
        self.last_prev = None
        self.samples = deque([(time.time(), 0)])

    # ---------------- connection ---------------- #
    def connect(self):
        self.status = "CONNECTING"
        self.close()
        s = socket.create_connection((self.host, self.port), timeout=10)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if hasattr(socket, "TCP_KEEPIDLE"):
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        except OSError:
            pass
        s.settimeout(10)
        self.sock = s
        if self.lost_since is None:
            self.log.write("INFO", "Connected to %s:%d" % (self.host, self.port))
        self.buf = b""
        self.en1 = None
        self.job = None
        self.pending.clear()
        self.last_rx = time.time()
        self._send(1, "mining.subscribe", ["pysolominer/" + VERSION])
        self._send(2, "mining.authorize", [self.user, self.password])
        deadline = time.time() + 15
        while self.en1 is None:
            if time.time() > deadline:
                raise ConnectionError("pool did not answer subscribe")
            self.pump(1)
        self.status = "CONNECTED"
        if self.lost_since is not None:
            gap = time.time() - self.lost_since
            self.reconnects += 1
            self.log.write("INFO", "Reconnected after %s" % fmt_dur(gap))
            self.lost_since = None
            self.lost_announced = False

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None

    def _send(self, mid, method, params):
        data = (json.dumps({"id": mid, "method": method, "params": params}) + "\n").encode()
        self.sock.sendall(data)

    def pump(self, timeout=0):
        r, _, _ = select.select([self.sock], [], [], timeout)
        if not r:
            return
        data = self.sock.recv(65536)
        if not data:
            raise ConnectionError("pool closed the connection")
        self.last_rx = time.time()
        self.buf += data
        while b"\n" in self.buf:
            line, self.buf = self.buf.split(b"\n", 1)
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            self.handle(msg)

    # ---------------- stratum messages ---------------- #
    def handle(self, msg):
        method = msg.get("method")
        mid = msg.get("id")
        if method:
            p = msg.get("params") or []
            if method == "mining.notify":
                job = Job(p)
                if self.last_prev is None:
                    kind = "first job"
                else:
                    kind = "clean" if job.clean else "update"
                    if job.prev != self.last_prev:
                        self.log.write("BLOCK", "New block on network | now mining height %s" % (job.height or "?"))
                self.last_prev = job.prev
                self.job = job
                self.job_seq += 1
                self.log.write("JOB", "New job %s (%s) | height %s" % (job.id, kind, job.height or "?"))
            elif method == "mining.set_difficulty":
                self.pool_diff = float(p[0]) or 1.0
                self.share_target = int(DIFF1 / self.pool_diff)
                self.log.write("INFO", "Pool difficulty set to %s" % fmt_diff(self.pool_diff))
            elif method == "mining.set_extranonce":
                self.en1 = bytes.fromhex(p[0])
                self.en2_size = int(p[1])
            elif method == "client.reconnect":
                raise ConnectionError("pool asked us to reconnect")
            elif method == "client.show_message":
                self.log.write("POOL", str(p[0]) if p else "")
            return

        if mid == 1:
            res = msg.get("result")
            if not res:
                raise ConnectionError("subscribe failed: %s" % msg.get("error"))
            self.en1 = bytes.fromhex(res[1])
            self.en2_size = int(res[2])
        elif mid == 2:
            if not msg.get("result"):
                raise FatalError("Pool rejected the worker/address: %s" % (msg.get("error"),))
        elif mid in self.pending:
            diff, is_block, _ = self.pending.pop(mid)
            if msg.get("result"):
                self.accepted += 1
                self.accepted_diff += diff
                self.last_share = "ACCEPTED (diff %s)" % fmt_diff(diff)
                self.log.write("SHARE", "Accepted share, diff %s" % fmt_diff(diff))
                if is_block:
                    self.blocks_found += 1
                    self.log.write("FOUND", "*** BLOCK ACCEPTED BY POOL! ***")
            else:
                self.rejected += 1
                err = msg.get("error")
                reason = err[1] if isinstance(err, (list, tuple)) and len(err) > 1 else str(err)
                self.last_share = "REJECTED (%s)" % reason
                self.log.write("SHARE", "Rejected share: %s" % reason)

    # ---------------- mining ---------------- #
    def make_work(self, job, en2):
        en2b = en2.to_bytes(self.en2_size, "big")
        header = build_prefix(job, self.en1, en2b)            # 76 bytes
        return hashlib.sha256(header[:64]), header[64:], en2b.hex()

    def hash_chunk(self, job, mid, tail, en2_hex, start, count):
        sha256 = hashlib.sha256
        target = self.share_target
        net_target = job.net_target
        for nonce in range(start, start + count):
            h = mid.copy()
            h.update(tail + PACK_NONCE(nonce))
            d = sha256(h.digest()).digest()
            if d[-2:] == ZERO2:                      # rare: cheap pre-filter
                val = int.from_bytes(d, "little")
                dif = DIFF1 / val if val else float("inf")
                if dif > self.best_diff:
                    self.best_diff = dif
                if val <= target:
                    is_block = val <= net_target
                    self.submit(job, en2_hex, nonce, is_block)

    def submit(self, job, en2_hex, nonce, is_block):
        self.sid += 1
        self.pending[self.sid] = (self.pool_diff, is_block, time.time())
        if is_block:
            self.log.write("FOUND", "*** BLOCK CANDIDATE FOUND - submitting! ***")
        self._send(self.sid, "mining.submit",
                   [self.user, job.id, en2_hex, job.ntime_hex, nonce_hex(nonce)])

    def mine(self):
        seq = -1
        job = mid = tail = en2_hex = None
        en2 = nonce = 0
        while True:
            self.pump(0)
            now = time.time()
            if now - self.last_rx > IDLE_TIMEOUT:
                raise ConnectionError("pool timeout (no data for %ds)" % IDLE_TIMEOUT)
            # drop stale pending submits (no answer for 60 s)
            for k in [k for k, v in self.pending.items() if now - v[2] > 60]:
                self.pending.pop(k, None)
            self.stats_tick()

            if self.job is None:
                self.pump(0.25)
                continue
            if seq != self.job_seq:
                job, seq, en2, nonce = self.job, self.job_seq, 0, 0
                mid, tail, en2_hex = self.make_work(job, en2)
            elif nonce >= 2 ** 32:
                en2 = (en2 + 1) % (2 ** (8 * self.en2_size))
                nonce = 0
                mid, tail, en2_hex = self.make_work(job, en2)

            count = min(CHUNK, 2 ** 32 - nonce)
            self.hash_chunk(job, mid, tail, en2_hex, nonce, count)
            nonce += count
            self.hashes += count

    def run(self):
        while True:
            try:
                self.connect()
                self.mine()
            except FatalError:
                raise
            except (OSError, ValueError) as e:
                if self.lost_since is None:
                    self.lost_since = time.time()
                    self.log.write("LOST", "Connection lost: %s" % e)
                self.lost_reason = str(e)
                self.close()
                self.status = "LOST"
                if not self.lost_announced:
                    self.lost_announced = True
                    self.log.write("INFO", "Retrying every %ds until the connection is back" % RECONNECT_DELAY)
                for _ in range(RECONNECT_DELAY):
                    self.stats_tick()
                    time.sleep(1)

    # ---------------- statistics ---------------- #
    def hashrate(self):
        now = time.time()
        window = max(15.0, self.refresh)
        while len(self.samples) > 1 and now - self.samples[1][0] > window:
            self.samples.popleft()
        t0, h0 = self.samples[0]
        return (self.hashes - h0) / (now - t0) if now > t0 else 0.0

    def stats_tick(self):
        now = time.time()
        if now - self.samples[-1][0] >= 1:
            self.samples.append((now, self.hashes))
        if now - self.last_snapshot > 300:
            self.last_snapshot = now
            self.log.write("STAT", "hashrate %s | accepted %d | rejected %d | best %s | uptime %s" % (
                fmt_rate(self.hashes / max(now - self.start, 1e-9)), self.accepted, self.rejected,
                fmt_diff(self.best_diff), fmt_dur(now - self.start)), show=False)
        if now - self.last_draw >= self.refresh:
            self.last_draw = now
            self.print_stats(now)

    def print_stats(self, now):
        job = self.job
        net = job.net_diff if job else None
        cur = self.hashrate() if self.status == "CONNECTED" else 0.0

        def paint(text, color):
            return "%s%s%s" % (color, text, RESET) if color else text

        def row(k, v, color=""):
            return "  %-22s%s" % (k, paint(v, color))

        if self.status == "CONNECTED":
            status = paint("CONNECTED", GREEN)
        elif self.status == "LOST":
            status = paint("CONNECTION LOST", RED) + " (retrying)"
        else:
            status = "CONNECTING..."

        L = [
            "",
            "---- STATISTICS %s " % datetime.now().strftime("%H:%M:%S") + "-" * 27,
            row("Status", status),
            row("Pool", "%s:%d" % (self.host, self.port)),
            row("Uptime", fmt_dur(now - self.start)),
            row("Hashrate", fmt_rate(cur)),
            row("Pool difficulty", fmt_diff(self.pool_diff)),
            row("Network difficulty", fmt_diff(net)),
            row("Accepted difficulty", fmt_diff(self.accepted_diff), GREEN if self.accepted_diff else ""),
            row("Best share", fmt_diff(self.best_diff)),
            row("Shares accepted", str(self.accepted), GREEN if self.accepted else ""),
            row("Shares rejected", str(self.rejected), RED if self.rejected else ""),
            row("Block height", str(job.height) if job and job.height else "-"),
            row("Blocks found", str(self.blocks_found), GREEN if self.blocks_found else ""),
            "",
        ]
        print("\n".join(L), flush=True)


# --------------------------------------------------------------------------- #
# self test (Bitcoin genesis block)
# --------------------------------------------------------------------------- #
def selftest():
    # 1) raw header of the Bitcoin genesis block
    header = (struct.pack("<I", 1) + bytes(32) +
              bytes.fromhex("3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a") +
              struct.pack("<III", 1231006505, 0x1D00FFFF, 2083236893))
    mid = hashlib.sha256(header[:64])
    mid.update(header[64:])
    h = hashlib.sha256(mid.digest()).digest()[::-1].hex()
    ok1 = h == "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    print("Genesis block hash : %s  [%s]" % (h, "OK" if ok1 else "FAIL"))

    # 2) same block rebuilt the way a Stratum pool would send it (coinbase split + extranonces)
    cb = bytes.fromhex(
        "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104"
        "455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365"
        "636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967"
        "f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c"
        "702b6bf11d5fac00000000")
    en1, en2b = cb[60:64], cb[64:68]
    job = Job(["t", "00" * 32, cb[:60].hex(), cb[68:].hex(), [], "00000001", "1d00ffff", "495fab29", True])
    prefix = build_prefix(job, en1, en2b)
    ok2 = prefix == header[:76]
    print("Stratum header build: [%s]" % ("OK" if ok2 else "FAIL"))

    # 3) the nonce string a pool expects for the genesis nonce (big-endian hex of the number)
    ok3 = nonce_hex(2083236893) == "7c2bac1d"
    print("Share nonce format  : %s  [%s]" % (nonce_hex(2083236893), "OK" if ok3 else "FAIL"))

    ok4 = abs(DIFF1 / nbits_to_target(0x1D00FFFF) - 1.0) < 1e-12
    print("Difficulty of 1d00ffff == 1 : [%s]" % ("OK" if ok4 else "FAIL"))
    return 0 if (ok1 and ok2 and ok3 and ok4) else 1


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="pysolominer - single-threaded solo Bitcoin miner")
    ap.add_argument("--url", help="pool host:port, e.g. pool.example.com:3333 (prompted if omitted)")
    ap.add_argument("--address", help="your Bitcoin address (rewards go here)")
    ap.add_argument("--worker", default="", help="optional worker name")
    ap.add_argument("--password", default="x", help="pool password (default x)")
    ap.add_argument("--refresh", type=float, default=30.0,
                    help="seconds between statistics blocks (default 30, minimum 1)")
    ap.add_argument("--selftest", action="store_true", help="verify hashing against the genesis block and exit")
    a = ap.parse_args()

    if a.selftest:
        sys.exit(selftest())

    addr = a.address or input("Enter your Bitcoin address: ").strip()
    if not re.match(r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$", addr):
        sys.exit("That does not look like a valid Bitcoin mainnet address.")
    user = addr + ("." + a.worker if a.worker else "")

    url = (a.url or input("Enter pool address (host:port): ").strip())
    url = url.replace("stratum+tcp://", "").replace("tcp://", "").strip("/")
    host, _, port = url.rpartition(":")
    if not host or not port.isdigit():
        sys.exit("Pool must look like host:port, e.g. pool.example.com:3333")

    if os.name == "nt":
        os.system("")                       # enable ANSI colours in cmd / PowerShell

    log = Logger(LOG_FILE)
    log.write("INFO", "pysolominer %s started | pool %s:%s | worker %s" % (VERSION, host, port, user))
    miner = Miner(host, int(port), user, a.password, log, max(1.0, a.refresh))
    try:
        miner.run()
    except KeyboardInterrupt:
        pass
    except FatalError as e:
        log.write("FATAL", str(e))
        print("\nFATAL: %s" % e)
        sys.exit(1)
    finally:
        miner.close()
        log.write("INFO", "Stopped by user | accepted %d | rejected %d | hashes %s" % (
            miner.accepted, miner.rejected, fmt_int(miner.hashes)), show=False)
    print("\nStopped. Accepted: %d  Rejected: %d  Total hashes: %s" % (
        miner.accepted, miner.rejected, fmt_int(miner.hashes)))


if __name__ == "__main__":
    main()
