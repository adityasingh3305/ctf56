#!/usr/bin/env python3
"""Solver per user's provided script, extended:
 - fixes nothing in their logic, just adds printable-check and more key variants
 - Test 1: random.seed(ts); randbytes(32) -> Salsa20 / ChaCha20 / AES-CTR
 - Test 2: random.seed(ts); randrange(256) keystream XOR
 - Extra: randbytes(16/24), sha256 keys, glibc rand(), counter-start-1 variants
"""
import base64, random, time, calendar, hashlib, struct, sys
from Crypto.Cipher import Salsa20, ChaCha20, AES

ciphertext = base64.b64decode("/QuCUtzvX5n3x/c3OPyV4MAF7Y749Mjn4Q==")
nonce = bytes.fromhex("7e197b75b71d8956")
base_ts = calendar.timegm(time.strptime("2026-09-20T04:37:00Z", "%Y-%m-%dT%H:%M:%SZ"))
print(f"base epoch = {base_ts}")  # sanity: their comment said 1792471020, code computes real value

def report(pt, method, seed):
    printable = all(32 <= b < 127 for b in pt)
    if b"Lun4r" in pt or b"flag" in pt.lower() or printable:
        print(f"[+] HIT {method} seed={seed!r}")
        print(f"    raw: {pt!r}")
        if printable:
            print(f"    flag: {pt.decode()}")
        return True
    return False

def try_all(key, method, seed):
    hits = []
    for cname, mk in (("Salsa20", lambda: Salsa20.new(key=key, nonce=nonce)),
                      ("ChaCha20", lambda: ChaCha20.new(key=key, nonce=nonce)),
                      ("ChaCha20ctr1", lambda: ChaCha20.new(key=key, nonce=nonce, initial_counter=1) if hasattr(ChaCha20, 'new') else None),
                      ("AES-CTR", lambda: AES.new(key, AES.MODE_CTR, nonce=nonce)),
                      ("AES-CTR1", lambda: AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=1))):
        try:
            c = mk()
            if c is None: continue
            pt = c.decrypt(ciphertext)
            if report(pt, f"{method}|{cname}", seed):
                hits.append((method, cname))
        except Exception:
            pass
    return hits

def glibc_rand_stream(seed, n):
    """glibc TYPE_3 rand(): r[i]=r[i-3]+r[i-31], out = r[i]>>1"""
    r = [0]*(34 + n)
    r[0] = seed & 0xffffffff
    for i in range(1, 31):
        r[i] = (16807 * r[i-1]) % 2147483647
        if r[i] < 0:
            r[i] += 2147483647
    for i in range(31, 34 + n):
        r[i] = (r[i-31] + r[i-3]) & 0xffffffff
    return [(r[i] >> 1) & 0xff for i in range(34, 34 + n)]

found = []
lo = int(sys.argv[1]) if len(sys.argv) > 1 else -30
hi = int(sys.argv[2]) if len(sys.argv) > 2 else 31
t_start = time.time()

for offset in range(lo, hi):
    ts = base_ts + offset
    seeds = {"int": ts, "float": float(ts), "str": str(ts)}

    for sname, seed in seeds.items():
        # Test 1: randbytes(32)
        rng = random.Random(); rng.seed(seed)
        key = rng.randbytes(32)
        found += try_all(key, f"randbytes32[{sname}]", seed)
        rng = random.Random(); rng.seed(seed)
        k16 = rng.randbytes(16)
        found += try_all(k16, f"randbytes16[{sname}]", seed)
        # Test 2: randrange keystream XOR (their direct test)
        rng = random.Random(); rng.seed(seed)
        ks = bytes(rng.randrange(256) for _ in range(len(ciphertext)))
        pt = bytes(a ^ b for a, b in zip(ciphertext, ks))
        if report(pt, f"XOR-randrange[{sname}]", seed):
            found.append((sname, "xor"))
        # getrandbits(256) big-endian
        rng = random.Random(); rng.seed(seed)
        keybe = rng.getrandbits(256).to_bytes(32, "big")
        found += try_all(keybe, f"getrandbitsBE[{sname}]", seed)
        # sha256 of string forms
        if sname in ("int", "str"):
            for kname, kb in (("sha256(str)", str(seed).encode()),
                              ("sha256(float)", struct.pack("<d", float(ts)))):
                found += try_all(hashlib.sha256(kb).digest(), f"{kname}[{sname}]", seed)
        # glibc rand() variants
        g = glibc_rand_stream(ts, 32)
        found += try_all(bytes(g), f"glibc-bytes[{sname}]", seed)
        found += try_all(b"".join(struct.pack("<I", (g[i] | (g[i+1] << 8) | (g[i+2] << 16) | ((g[i+3] & 0x7f) << 24))) for i in range(0, 32, 4)), f"glibc-dwords[{sname}]", seed)

    if offset % 10 == 0:
        print(f"  .. offset {offset:+d} ({time.time()-t_start:.0f}s)", flush=True)

print(f"\ndone in {time.time()-t_start:.0f}s; hits: {found if found else 'NONE'}")
