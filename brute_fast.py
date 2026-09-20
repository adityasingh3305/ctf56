#!/usr/bin/env python3
"""Fast multiprocess sweep: time-seeded keys at ms/us granularity.

Candidate seeds: int(ms), float t, str(t) forms, int(us), int(ns), glibc srand
Keygens: random.randbytes(32/16/24), getrandbits(256) BE, sha256(str), glibc stream
Ciphers: ChaCha20, Salsa20, AES-CTR (nonce 8B; ctr0 + ctr1 variants)
Checks:  5-byte keystream printable -> full decrypt printable / contains Lun4r
Oracle:  PRNG nonce reproduction (randbytes(8) before or after key draw)
"""
import base64, hashlib, random, struct, sys, time
from multiprocessing import Pool
from Crypto.Cipher import ChaCha20, Salsa20, AES

CT = base64.b64decode("/QuCUtzvX5n3x/c3OPyV4MAF7Y749Mjn4Q==")
NONCE = bytes.fromhex("7e197b75b71d8956")
BASE = 1789879020.0  # 2026-09-20T04:37:00Z
FLAG_PREF = b"Lun4r"

def printable(bs):
    return all(32 <= b < 127 for b in bs)

def full_check(key):
    """Try all ciphers with this key; return hit description or None."""
    def chacha_c1():
        c = ChaCha20.new(key=key, nonce=NONCE)
        c.encrypt(b"\x00" * 32)  # discard block 0 -> keystream starts at block 1
        return c
    for cname, mk in (
        ("ChaCha20", lambda: ChaCha20.new(key=key, nonce=NONCE)),
        ("Salsa20",  lambda: Salsa20.new(key=key, nonce=NONCE)),
        ("AES-CTR",  lambda: AES.new(key, AES.MODE_CTR, nonce=NONCE)),
        ("ChaCha20c1", chacha_c1),
        ("AES-CTRc1",  lambda: AES.new(key, AES.MODE_CTR, nonce=NONCE, initial_value=1)),
    ):
        try:
            c = mk(); pt = c.encrypt(CT)
        except ValueError:
            continue
        if FLAG_PREF in pt or printable(pt):
            return f"{cname} key={key.hex()} pt={pt!r}"
    return None

def gen_keys(t_float):
    """Yield (label, key) for every key-derivation variant at time t_float."""
    ms = int(round(t_float * 1000))
    us = int(round(t_float * 1_000_000))
    ns = int(round(t_float * 1_000_000_000))
    t_str = str(t_float)
    t_fix = f"{t_float:.6f}"

    # PRNG-seeded variants
    for sname, seed in (("f", t_float), ("ms", ms), ("us", us), ("ns", ns),
                        ("i", int(t_float)), ("s", t_str), ("s6", t_fix)):
        rng = random.Random(seed)
        yield f"rb32[{sname}]", rng.randbytes(32)
        rng = random.Random(seed)
        yield f"rb16[{sname}]", rng.randbytes(16)
        rng = random.Random(seed)
        yield f"rb24[{sname}]", rng.randbytes(24)
        rng = random.Random(seed)
        yield f"be256[{sname}]", rng.getrandbits(256).to_bytes(32, "big")

    # hash variants
    for sname, sb in (("ms", str(ms).encode()), ("us", str(us).encode()),
                      ("ns", str(ns).encode()), ("i", str(int(t_float)).encode()),
                      ("s", t_str.encode()), ("s6", t_fix.encode())):
        yield f"sha256[{sname}]", hashlib.sha256(sb).digest()
        yield f"md5[{sname}]", hashlib.md5(sb).digest() * 2
        yield f"sha1[{sname}]", (hashlib.sha1(sb).digest() + hashlib.sha1(sb).digest())[:32]

    # glibc srand/rand variants (seed truncated to unsigned int)
    gseed = ms & 0xFFFFFFFF
    r = [0] * 66
    r[0] = gseed
    for i in range(1, 31):
        r[i] = (16807 * r[i-1]) % 2147483647
    for i in range(31, 66):
        r[i] = (r[i-31] + r[i-3]) & 0xFFFFFFFF
    out = [(r[i] >> 1) for i in range(34, 66)]
    yield "glibc-bytes", bytes(v & 0xFF for v in out)
    yield "glibc-dwLE", b"".join(struct.pack("<I", v & 0xFFFFFFFF) for v in out)[:32]

def nonce_oracle(t_float):
    """If key and nonce both came from the same PRNG stream, reproduce nonce."""
    hits = []
    ms = int(round(t_float * 1000)); us = int(round(t_float * 1_000_000))
    for seed in (t_float, ms, us, int(t_float)):
        # nonce first, then key
        rng = random.Random(seed)
        if rng.randbytes(8) == NONCE:
            k = rng.randbytes(32)
            hits.append(("nonce-then-key", seed, k))
        # key first, then nonce
        rng = random.Random(seed)
        k = rng.randbytes(32)
        if rng.randbytes(8) == NONCE:
            hits.append(("key-then-nonce", seed, k))
    return hits

def work(args):
    mode, start, count = args
    step = 1.0 / (1000 if mode == "ms" else 1_000_000)
    t0 = time.time(); n = 0
    for i in range(start, start + count):
        t = BASE + i * step
        # nonce oracle first (cheap, no cipher needed)
        for how, seed, key in nonce_oracle(t):
            res = full_check(key)
            if res:
                return f"[!!] ORACLE {how} seed={seed!r} t={t!r}: {res}"
        for label, key in gen_keys(t):
            n += 1
            res = full_check(key)
            if res:
                return f"[!!] HIT {label} t={t!r} ({time.time()-t0:.0f}s): {res}"
    return f"chunk {mode} [{start}:{start+count}] done {n} keys in {time.time()-t0:.0f}s"

if __name__ == "__main__":
    mode = sys.argv[1]          # "ms" or "us"
    lo = int(sys.argv[2])       # sub-second offset range start (units of mode)
    hi = int(sys.argv[3])       # end
    NPROC = 2
    total = hi - lo
    chunk = max(1, total // (NPROC * 8))
    jobs = [(mode, s, min(chunk, hi - s)) for s in range(lo, hi, chunk)]
    print(f"sweep mode={mode} range=[{lo},{hi}) chunks={len(jobs)}", flush=True)
    t0 = time.time()
    with Pool(NPROC) as p:
        for res in p.imap_unordered(work, jobs):
            print(res, flush=True)
    print(f"ALL DONE in {time.time()-t0:.0f}s")
