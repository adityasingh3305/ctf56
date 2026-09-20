#!/usr/bin/env python3
"""Brute-force time-derived keys for 'The Key That Wasn't Random'.

Record:
  ciphertext /QuCUtzvX5n3x/c3OPyV4MAF7Y749Mjn4Q==  (25 bytes)
  created_at 2026-09-20T04:37:00Z   (truncated to the second/minute)
  nonce      7e197b75b71d8956       (8 bytes)
"""
import base64, hashlib, random, struct, sys, time as _time
from datetime import datetime, timezone
from Crypto.Cipher import ChaCha20, Salsa20, AES

CT = base64.b64decode("/QuCUtzvX5n3x/c3OPyV4MAF7Y749Mjn4Q==")
NONCE = bytes.fromhex("7e197b75b71d8956")
BASE = datetime(2026, 9, 20, 4, 37, 0, tzinfo=timezone.utc).timestamp()  # 1789879020.0
PREFIX = b"Lun4r{"

# expected keystream prefix for each cipher = ct[:5] XOR 'Lun4r'
KS_EXPECT = bytes(a ^ b for a, b in zip(CT[:5], PREFIX))

def key_candidates(t_float):
    """Yield (scheme_name, key_bytes) for a given precise timestamp."""
    out = []
    t_str = str(t_float)                      # e.g. '1789879020.123456'
    t_fix = f"{t_float:.6f}"
    t_int = int(t_float)
    t_ms = int(round(t_float * 1000))
    t_us = int(round(t_float * 1000000))
    t_ns = int(round(t_float * 1000000000))

    add = out.append
    add(("sha256(str(t))",        hashlib.sha256(t_str.encode()).digest()))
    add(("sha256(f%.6f)",         hashlib.sha256(t_fix.encode()).digest()))
    add(("sha256(str(ms))",       hashlib.sha256(str(t_ms).encode()).digest()))
    add(("sha256(str(us))",       hashlib.sha256(str(t_us).encode()).digest()))
    add(("sha256(str(ns))",       hashlib.sha256(str(t_ns).encode()).digest()))
    add(("sha256(str(int))",      hashlib.sha256(str(t_int).encode()).digest()))
    add(("sha256(dbl<8)",         hashlib.sha256(struct.pack("<d", t_float)).digest()))
    add(("sha256(dbl>8)",         hashlib.sha256(struct.pack(">d", t_float)).digest()))
    add(("sha256(ms u64 BE)",     hashlib.sha256(struct.pack(">Q", t_ms)).digest()))
    add(("sha256(us u64 BE)",     hashlib.sha256(struct.pack(">Q", t_us)).digest()))
    add(("md5(str(t))",           hashlib.md5(t_str.encode()).digest()))
    add(("sha1(str(t))",          hashlib.sha1(t_str.encode()).digest()))
    # iso-format with microseconds
    dt = datetime.fromtimestamp(t_float, tz=timezone.utc)
    add(("sha256(iso space)",     hashlib.sha256(dt.strftime("%Y-%m-%d %H:%M:%S.%f").encode()).digest()))
    add(("sha256(iso T)",         hashlib.sha256(dt.strftime("%Y-%m-%dT%H:%M:%S.%f").encode()).digest()))
    add(("sha256(iso+00:00)",     hashlib.sha256(dt.isoformat().encode()).digest()))
    # python random seeded by the timestamp
    for seedname, seed in (("rfloat", t_float), ("rms", t_ms), ("rus", t_us), ("rint", t_int)):
        rng = random.Random()
        rng.seed(seed)
        k = bytes(rng.getrandbits(8) for _ in range(32))
        add((f"rand8({seedname})", k))
        rng = random.Random()
        rng.seed(seed)
        n = rng.getrandbits(256)
        add((f"rand256({seedname})", n.to_bytes(32, "big")))
    return out

def keystreams(key):
    """Yield (cipher_name, keystream_prefix) for candidate ciphers."""
    try:
        c = ChaCha20.new(key=key, nonce=NONCE)
        yield ("chacha20", c.encrypt(b"\x00" * 5))
    except ValueError:
        pass
    if len(key) in (16, 32):
        try:
            c = Salsa20.new(key=key, nonce=NONCE)
            yield ("salsa20", c.encrypt(b"\x00" * 5))
        except ValueError:
            pass
    if len(key) in (16, 24, 32):
        try:
            c = AES.new(key, AES.MODE_CTR, nonce=NONCE)
            yield ("aes-ctr", c.encrypt(b"\x00" * 5))
        except ValueError:
            pass

def hit(ks):
    return ks == KS_EXPECT

def scan(offsets, verbose=False):
    t0 = _time.time()
    n = 0
    for off in offsets:
        t = BASE + off / 1_000_000.0
        for scheme, key in key_candidates(t):
            for cname, ks in keystreams(key):
                n += 1
                if hit(ks):
                    print(f"[!!] HIT scheme={scheme} cipher={cname} t={t!r} key={key.hex()}")
                    pt = None
                    c = ChaCha20.new(key=key, nonce=NONCE)
                    print("    chacha pt:", c.encrypt(CT))
                    return True
    dt = _time.time() - t0
    print(f"  scanned {n} key/cipher combos in {dt:.1f}s ({n/dt:.0f}/s)", flush=True)
    return False

if __name__ == "__main__":
    stage = sys.argv[1] if len(sys.argv) > 1 else "1"
    if stage == "1":
        # whole minute at millisecond granularity
        print("Stage 1: minute window, ms granularity (60000 offsets)")
        scan((i / 1000.0 for i in range(0, 60000)))
    elif stage == "2":
        # the single second 04:37:00.000000 - 04:37:00.999999 at us granularity
        print("Stage 2: second 04:37:00, us granularity (1e6 offsets)")
        scan((i / 1_000_000.0 for i in range(0, 1_000_000)))
    elif stage == "3":
        # whole minute at us granularity, in 1-second slices
        sec = int(sys.argv[2])
        print(f"Stage 3: second +{sec} of the minute, us granularity")
        scan(((sec * 1_000_000 + i) / 1_000_000.0 for i in range(0, 1_000_000)))
