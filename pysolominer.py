#!/usr/bin/env python3
"""pysolominer - a multi-process Bitcoin solo miner (Stratum v1) in pure Python.

Connects to a solo-mining pool, receives block
templates over Stratum, and searches nonces with all CPU cores. If a hash meets
the network target, the pool submits the block and the full reward goes to the
address you used as your username.

Solo mining is a free lottery: every hash is a ticket, and about every 10
minutes the Bitcoin network holds a draw (a new block). If one of your tickets
wins, the whole block reward is yours. A CPU holds only a few tickets, so play
for the fun of it. See README.md.
"""

import argparse
import errno
import hashlib
import json
import logging
import multiprocessing as mp
import os
import queue
import signal
import socket
import ssl
import struct
import sys
import threading
import time
from dataclasses import dataclass
from fractions import Fraction

__version__ = "1.0.0"

DIFF1_TARGET = 0xFFFF << 208
ZERO4 = b"\x00\x00\x00\x00"
_pack_u32 = struct.Struct("<I").pack

log = logging.getLogger("pysolominer")

# The log file always lives next to this script (or next to the .exe if frozen).
_APP_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
LOG_FILE = os.path.join(_APP_DIR, "pysolominer_log.txt")
LOG_MAX_MB = 1   # fixed: the log is cleared and restarted from the top at 1 MB


# --------------------------------------------------------------------------
# Bitcoin primitives
# --------------------------------------------------------------------------
def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def nbits_to_target(nbits_hex: str) -> int:
    n = int(nbits_hex, 16)
    exp, coeff = n >> 24, n & 0xFFFFFF
    return coeff << (8 * (exp - 3)) if exp > 3 else coeff >> (8 * (3 - exp))


def difficulty_to_target(difficulty: float) -> int:
    if difficulty <= 0:
        raise ValueError("difficulty must be positive")
    return int(Fraction(DIFF1_TARGET) / Fraction(difficulty))


def swap_words(b: bytes) -> bytes:
    """Stratum sends prevhash with each 4-byte word byte-swapped."""
    return b"".join(b[i:i + 4][::-1] for i in range(0, len(b), 4))


def merkle_root(coinbase_hash: bytes, branch) -> bytes:
    root = coinbase_hash
    for h in branch:
        root = sha256d(root + bytes.fromhex(h))
    return root


def build_header_prefix(version: str, prevhash: str, root: bytes,
                        ntime: str, nbits: str) -> bytes:
    """First 76 bytes of the block header (everything except the nonce)."""
    return (bytes.fromhex(version)[::-1]
            + swap_words(bytes.fromhex(prevhash))
            + root
            + bytes.fromhex(ntime)[::-1]
            + bytes.fromhex(nbits)[::-1])


def scan(prefix76: bytes, start: int, end: int, threshold: int, prefilter: bool):
    """Yield (nonce, digest) for every nonce in [start, end) whose double-SHA256
    (as a little-endian integer) is <= threshold.

    Uses a SHA-256 midstate: the first 64 header bytes are hashed once, only the
    final 16 bytes are re-hashed per nonce.
    """
    sha = hashlib.sha256
    pack = _pack_u32
    base = sha(prefix76[:64])
    tail = prefix76[64:]
    from_bytes = int.from_bytes
    for nonce in range(start, end):
        h = base.copy()
        h.update(tail + pack(nonce))
        d = sha(h.digest()).digest()
        if prefilter and d[28:] != ZERO4:
            continue
        if from_bytes(d, "little") <= threshold:
            yield nonce, d


# --------------------------------------------------------------------------
# Data passed between processes
# --------------------------------------------------------------------------
@dataclass
class Job:
    job_id: str
    prevhash: str
    coinb1: str
    coinb2: str
    branch: list
    version: str
    nbits: str
    ntime: str
    extranonce1: str
    en2_size: int
    share_target: int
    block_target: int
    gen: int
    session: int


@dataclass
class Result:
    job_id: str
    en2: str
    ntime: str
    nonce: str
    is_block: bool
    hash_hex: str
    session: int
    share_diff: float = 0.0   # pool difficulty this share was mined against


# --------------------------------------------------------------------------
# Worker process
# --------------------------------------------------------------------------
def mine_job(wid, nworkers, job, result_q, generation, counters, chunk):
    size = job.en2_size
    max_en2 = 256 ** size if size > 0 else 1
    en2 = wid % max_en2
    ntime_int = int(job.ntime, 16)
    threshold = max(job.share_target, job.block_target)
    prefilter = threshold < (1 << 224)

    while True:
        en2_hex = en2.to_bytes(size, "big").hex() if size > 0 else ""
        coinbase = bytes.fromhex(job.coinb1 + job.extranonce1 + en2_hex + job.coinb2)
        root = merkle_root(sha256d(coinbase), job.branch)
        ntime_hex = "%08x" % ntime_int
        prefix = build_header_prefix(job.version, job.prevhash, root, ntime_hex, job.nbits)

        for start in range(0, 1 << 32, chunk):
            if generation.value != job.gen:
                return
            end = min(start + chunk, 1 << 32)
            for nonce, d in scan(prefix, start, end, threshold, prefilter):
                val = int.from_bytes(d, "little")
                result_q.put(Result(job.job_id, en2_hex, ntime_hex, "%08x" % nonce,
                                    val <= job.block_target, d[::-1].hex(), job.session,
                                    DIFF1_TARGET / max(job.share_target, 1)))
            counters[wid] += end - start

        en2 += nworkers
        if en2 >= max_en2:       # extranonce2 space exhausted: roll ntime forward
            en2 = wid % max_en2
            ntime_int += 1


def worker_main(wid, nworkers, job_q, result_q, generation, counters, chunk):
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    while True:
        job = job_q.get()
        if job is None:
            return
        while True:  # always work on the newest job
            try:
                nxt = job_q.get_nowait()
            except queue.Empty:
                break
            if nxt is None:
                return
            job = nxt
        if generation.value != job.gen:
            continue
        try:
            mine_job(wid, nworkers, job, result_q, generation, counters, chunk)
        except Exception:  # never let a bad job kill the worker
            logging.getLogger("pysolominer").exception("worker %d error", wid)
            time.sleep(1)


# --------------------------------------------------------------------------
# Stratum client / coordinator
# --------------------------------------------------------------------------
NET_DOWN_ERRNOS = {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN, errno.ETIMEDOUT}


def enable_keepalive(s, idle=30, interval=10, count=3):
    """Make the OS probe the connection so a dead network is noticed in about a minute."""
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if sys.platform == "win32":
            s.ioctl(socket.SIO_KEEPALIVE_VALS, (1, idle * 1000, interval * 1000))
            return
        if hasattr(socket, "TCP_KEEPIDLE"):
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, idle)
        elif sys.platform == "darwin":
            s.setsockopt(socket.IPPROTO_TCP, 0x10, idle)  # TCP_KEEPALIVE
        if hasattr(socket, "TCP_KEEPINTVL"):
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval)
        if hasattr(socket, "TCP_KEEPCNT"):
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, count)
    except (OSError, AttributeError, ValueError):
        pass


def fmt_rate(hps: float) -> str:
    for unit, scale in (("GH/s", 1e9), ("MH/s", 1e6), ("kH/s", 1e3)):
        if hps >= scale:
            return f"{hps / scale:.2f} {unit}"
    return f"{hps:.2f} H/s"


def fmt_duration(seconds: float) -> str:
    s = int(max(seconds, 0))
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60:02d}s"
    if s < 86400:
        return f"{s // 3600}h {s % 3600 // 60:02d}m"
    return f"{s // 86400}d {s % 86400 // 3600:02d}h"


def fmt_diff(d: float) -> str:
    if d <= 0:
        return "n/a"
    for unit, scale in (("P", 1e15), ("T", 1e12), ("G", 1e9), ("M", 1e6)):
        if d >= scale:
            return f"{d / scale:.2f} {unit}"
    return f"{d:,.0f}" if abs(d - round(d)) < 1e-9 else f"{d:,.4g}"


class ClearingFileHandler(logging.FileHandler):
    """Log file that is created if missing and wiped (restarted from the top)
    whenever it grows past max_bytes."""

    def __init__(self, path, max_bytes):
        folder = os.path.dirname(os.path.abspath(path))
        os.makedirs(folder, exist_ok=True)
        super().__init__(path, mode="a", encoding="utf-8")
        self.max_bytes = max_bytes

    def emit(self, record):
        super().emit(record)
        try:
            if self.stream and os.fstat(self.stream.fileno()).st_size >= self.max_bytes:
                self.stream.flush()
                self.stream.truncate(0)
                self.stream.seek(0)
                self.stream.write("--- log cleared: size limit of %.1f MB reached ---\n"
                                  % (self.max_bytes / 1048576))
                self.stream.flush()
        except (OSError, ValueError):
            pass


def setup_logging(verbose, log_file, max_mb):
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S"))
    root.addHandler(console)
    if log_file:
        try:
            fh = ClearingFileHandler(log_file, int(max_mb * 1024 * 1024))
            fh.setLevel(logging.DEBUG)   # the file records everything
            fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s",
                                              "%Y-%m-%d %H:%M:%S"))
            root.addHandler(fh)
        except OSError as e:
            log.warning("cannot open log file %s (%s); logging to console only", log_file, e)


class Miner:
    def __init__(self, args):
        self.host, self.port = args.host, args.port
        self.user, self.password = args.user, args.password
        self.tls = args.tls
        self.nworkers = args.workers
        self.chunk = args.chunk

        self.stop = threading.Event()
        self.ctx = mp.get_context("spawn")
        self.generation = self.ctx.Value("Q", 0, lock=False)
        self.counters = self.ctx.Array("Q", self.nworkers, lock=False)
        self.result_q = self.ctx.Queue()
        self.job_qs = [self.ctx.Queue() for _ in range(self.nworkers)]
        self.procs = []

        self.sock = None
        self.send_lock = threading.Lock()
        self.session = 0
        self.extranonce1 = None
        self.en2_size = 4
        self.difficulty = 1.0
        self.net_diff = 0.0
        self.next_id = 100
        self.pending = {}
        self.accepted = 0
        self.rejected = 0
        self.blocks = 0
        self.gen = 0
        self.online = False
        self.offline_since = None
        self.stats_interval = getattr(args, "stats_interval", 30)
        self.started_at = time.time()
        self.connected_at = None
        self.last_job_at = None
        self.last_job_id = "-"
        self.last_share_at = None
        self.last_share_diff = 0.0

    # ---- lifecycle ----
    def start_workers(self):
        for i in range(self.nworkers):
            p = self.ctx.Process(
                target=worker_main, name=f"miner-{i}", daemon=True,
                args=(i, self.nworkers, self.job_qs[i], self.result_q,
                      self.generation, self.counters, self.chunk))
            p.start()
            self.procs.append(p)

    def shutdown(self):
        self.stop.set()
        self.generation.value += 1
        for q in self.job_qs:
            try:
                q.put(None)
            except Exception:
                pass
        for p in self.procs:
            p.join(timeout=3)
            if p.is_alive():
                p.terminate()
        self._close()

    def _close(self):
        s, self.sock = self.sock, None
        if s:
            try:
                s.close()
            except OSError:
                pass

    # ---- network ----
    def _send(self, obj):
        data = (json.dumps(obj) + "\n").encode()
        with self.send_lock:
            if self.sock is None:
                raise ConnectionError("not connected")
            self.sock.sendall(data)

    def _connect(self):
        log.info("connecting to %s:%d%s", self.host, self.port, " (TLS)" if self.tls else "")
        s = socket.create_connection((self.host, self.port), timeout=20)
        enable_keepalive(s)
        if self.tls:
            s = ssl.create_default_context().wrap_socket(s, server_hostname=self.host)
        s.settimeout(180)  # fallback: pools notify far more often than this
        self.sock = s
        self.session += 1
        self.extranonce1 = None
        self.pending.clear()

    def _lines(self):
        buf = b""
        while not self.stop.is_set():
            data = self.sock.recv(65536)
            if not data:
                raise ConnectionError("connection closed by pool")
            buf += data
            if len(buf) > (1 << 20) and b"\n" not in buf:
                raise ConnectionError("oversized message from pool")
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if line.strip():
                    try:
                        yield json.loads(line)
                    except ValueError:
                        log.warning("ignoring malformed line from pool")

    def serve(self):
        self._connect()
        self._send({"id": 1, "method": "mining.subscribe", "params": [f"pysolominer/{__version__}"]})
        for msg in self._lines():
            self._handle(msg)

    def _handle(self, msg):
        method = msg.get("method")
        if method == "mining.notify":
            self._on_notify(msg["params"])
        elif method == "mining.set_difficulty":
            self.difficulty = float(msg["params"][0])
            log.info("pool difficulty set to %g", self.difficulty)
        elif method == "client.reconnect":
            raise ConnectionError("pool requested reconnect")
        elif method is not None:
            log.debug("unhandled method %s", method)
        else:
            self._on_response(msg)

    def _on_response(self, msg):
        mid, result, err = msg.get("id"), msg.get("result"), msg.get("error")
        if mid == 1:
            if err or not result:
                raise ConnectionError(f"subscribe failed: {err}")
            self.extranonce1 = result[1]
            self.en2_size = int(result[2])
            log.info("subscribed (extranonce1=%s, extranonce2_size=%d)", self.extranonce1, self.en2_size)
            self._send({"id": 2, "method": "mining.authorize", "params": [self.user, self.password]})
        elif mid == 2:
            if result is True:
                log.info("authorized as %s", self.user)
                if self.offline_since is not None:
                    log.info("Internet/pool connection restored after %.0fs - mining resumed",
                             time.time() - self.offline_since)
                self.offline_since = None
                self.connected_at = time.time()
                self.online = True
            else:
                log.error("authorization FAILED (%s). Check your address.", err or result)
                self.stop.set()
        elif mid in self.pending:
            r = self.pending.pop(mid)
            if result is True:
                self.accepted += 1
                self.last_share_at = time.time()
                self.last_share_diff = r.share_diff
                if r.is_block:
                    self.blocks += 1
                    log.warning("*** BLOCK ACCEPTED *** hash=%s", r.hash_hex)
                else:
                    log.info("share accepted | difficulty %.4g (%d accepted / %d rejected)",
                             r.share_diff, self.accepted, self.rejected)
            else:
                self.rejected += 1
                log.warning("share rejected: %s", err or result)

    def _on_notify(self, p):
        if self.extranonce1 is None:
            return
        try:
            job_id, prevhash, coinb1, coinb2, branch, version, nbits, ntime = p[:8]
            if len(prevhash) != 64 or len(nbits) != 8 or len(version) != 8 or len(ntime) != 8:
                raise ValueError("bad field length")
            bytes.fromhex(coinb1 + coinb2)
            job_gen = self.gen + 1
            job = Job(job_id, prevhash, coinb1, coinb2, list(branch), version, nbits, ntime,
                      self.extranonce1, self.en2_size,
                      difficulty_to_target(self.difficulty), nbits_to_target(nbits),
                      job_gen, self.session)
        except (ValueError, TypeError, IndexError) as e:
            log.warning("bad mining.notify ignored: %s", e)
            return
        self.gen = job_gen
        self.net_diff = DIFF1_TARGET / max(job.block_target, 1)
        for q in self.job_qs:
            q.put(job)
        self.generation.value = job_gen
        self.last_job_at = time.time()
        self.last_job_id = job_id
        log.info("new job %s (clean=%s)", job_id, p[8] if len(p) > 8 else "?")
        log.debug("job %s: prevhash=%s nbits=%s ntime=%s version=%s merkle_branches=%d network_diff=%.4g",
                  job_id, prevhash, nbits, ntime, version, len(branch), self.net_diff)

    # ---- submit + stats threads ----
    def submit_loop(self):
        while not self.stop.is_set():
            try:
                r = self.result_q.get(timeout=1)
            except queue.Empty:
                continue
            if r.session != self.session:
                log.info("dropping result from an old connection")
                continue
            if r.is_block:
                log.warning("*** BLOCK CANDIDATE FOUND *** hash=%s", r.hash_hex)
            log.debug("submitting share: job=%s extranonce2=%s ntime=%s nonce=%s hash=%s",
                      r.job_id, r.en2, r.ntime, r.nonce, r.hash_hex)
            try:
                self.next_id += 1
                mid = self.next_id
                self.pending[mid] = r
                self._send({"id": mid, "method": "mining.submit",
                            "params": [self.user, r.job_id, r.en2, r.ntime, r.nonce]})
            except (OSError, ConnectionError) as e:
                log.warning("submit failed: %s", e)

    def stats_report(self, rates):
        now = time.time()
        uptime = now - self.started_at
        avg = sum(self.counters) / max(uptime, 1e-9)
        alive = [i < len(self.procs) and self.procs[i].is_alive() for i in range(self.nworkers)]
        bar = "=" * 62

        def row(label, value):
            return f"  {label:<11}: {value}"

        lines = ["", bar, "  MINER STATS".ljust(62), bar]
        if self.online:
            since = fmt_duration(now - self.connected_at) if self.connected_at else "?"
            lines.append(row("Status", f"ONLINE (connected for {since})"))
        else:
            off = fmt_duration(now - self.offline_since) if self.offline_since else "?"
            lines.append(row("Status", f"OFFLINE for {off} - reconnecting, mining paused"))
        lines.append(row("Uptime", fmt_duration(uptime)))
        lines.append(row("Pool", f"{self.host}:{self.port}"))
        lines.append(row("Worker", self.user))
        lines.append(row("Hashrate", f"{fmt_rate(sum(rates))} now | {fmt_rate(avg)} average"))
        lines.append(row("Difficulty", f"pool {fmt_diff(self.difficulty)} | network {fmt_diff(self.net_diff)}"))
        lines.append(row("Shares", f"{self.accepted} accepted | {self.rejected} rejected | "
                                   f"{self.blocks} blocks found"))
        if self.last_share_at:
            lines.append(row("Last share", f"{fmt_duration(now - self.last_share_at)} ago "
                                           f"(difficulty {fmt_diff(self.last_share_diff)})"))
        else:
            lines.append(row("Last share", "none yet"))
        if self.last_job_at:
            lines.append(row("Last job", f"{fmt_duration(now - self.last_job_at)} ago (id {self.last_job_id})"))
        else:
            lines.append(row("Last job", "waiting for the first job"))
        lines.append(row("Workers", f"{sum(alive)} of {self.nworkers} running"))
        for i, r in enumerate(rates):
            state = fmt_rate(r) if alive[i] else "NOT RUNNING"
            lines.append(f"      #{i:<3} {state}")
        lines.append(bar)
        return "\n".join(lines)

    def stats_loop(self, interval=None):
        interval = interval or self.stats_interval
        last, t0 = list(self.counters), time.time()
        while not self.stop.wait(interval):
            now = time.time()
            cur = list(self.counters)
            dt = max(now - t0, 1e-9)
            rates = [(c - l) / dt for c, l in zip(cur, last)]
            last, t0 = cur, now
            log.info("%s", self.stats_report(rates))

    def run(self):
        self.start_workers()
        for fn in (self.submit_loop, self.stats_loop):
            threading.Thread(target=fn, daemon=True).start()
        backoff = 1
        while not self.stop.is_set():
            started = time.time()
            err = None
            try:
                self.serve()
            except (OSError, ConnectionError, ssl.SSLError) as e:
                err = e
            self._close()
            self.generation.value += 1   # stop work built on a dead session
            self.gen = self.generation.value
            if self.stop.is_set():
                break
            if time.time() - started > 60:
                backoff = 1
            self.online = False
            self.connected_at = None
            if self.offline_since is None:
                self.offline_since = time.time()
            if err is not None:
                if isinstance(err, (socket.gaierror, socket.timeout)) or \
                        getattr(err, "errno", None) in NET_DOWN_ERRNOS:
                    log.warning("No internet connection or pool unreachable (%s). "
                                "Retrying in %ds ...", err, backoff)
                else:
                    log.warning("Disconnected from pool (%s). Reconnecting in %ds ...", err, backoff)
            if self.stop.wait(backoff):
                break
            backoff = min(backoff * 2, 60)


# --------------------------------------------------------------------------
def parse_args(argv=None):
    ap = argparse.ArgumentParser(description="Pure-Python Bitcoin solo miner (Stratum v1)")
    ap.add_argument("--url", required=True,
                    help="pool address: stratum+tcp://host:port or stratum+ssl://host:port")
    ap.add_argument("--user", help="your Bitcoin address (optionally ADDRESS.workername)")
    ap.add_argument("--password", default="x")
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--chunk", type=int, default=100_000, help="nonces per work slice")
    ap.add_argument("--stats-interval", type=int, default=30, help="seconds between stats reports")
    ap.add_argument("-v", "--verbose", action="store_true", help="also show debug lines on the console")
    a = ap.parse_args(argv)

    if not a.user:
        ap.error("--user (your Bitcoin address) is required")
    a.tls = False
    u = a.url
    for prefix, tls in (("stratum+tcp://", False), ("stratum+ssl://", True), ("stratum+tls://", True)):
        if u.startswith(prefix):
            u, a.tls = u[len(prefix):], tls
    host, _, port = u.partition(":")
    if not host or not port.isdigit():
        ap.error("bad --url; expected stratum+tcp://host:port")
    a.host, a.port = host, int(port)
    if a.workers < 1:
        ap.error("--workers must be >= 1")
    if a.stats_interval < 1:
        ap.error("--stats-interval must be >= 1")
    return a


def main(argv=None):
    args = parse_args(argv)
    setup_logging(args.verbose, LOG_FILE, LOG_MAX_MB)
    miner = Miner(args)
    signal.signal(signal.SIGTERM, lambda *_: miner.stop.set())
    log.info("pysolominer %s: %d workers", __version__, args.workers)
    try:
        miner.run()
    except KeyboardInterrupt:
        pass
    finally:
        log.info("shutting down")
        miner.shutdown()
    return 0


if __name__ == "__main__":
    mp.freeze_support()
    sys.exit(main())
