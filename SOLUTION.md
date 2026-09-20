# The Moon Knows the Time — "The Key That Wasn't Random" (200 pts)

**Flag: `Lun4r{t1m3_1s_n0t_4_prng}`**

## Target

`http://key.chall.rootriet.in` serves a static incident record:

```json
{
  "ciphertext": "/QuCUtzvX5n3x/c3OPyV4MAF7Y749Mjn4Q==",
  "created_at": "2026-09-20T04:37:00Z",
  "nonce": "7e197b75b71d8956",
  "request_id": "req-caedab44045c"
}
```

## Analysis

1. **Ciphertext is 25 bytes** — no block padding ⇒ a stream cipher (or CTR mode).
2. **Nonce is 8 bytes** — fits ChaCha20 / Salsa20 / AES-CTR (nonce half of the counter block).
3. The hints ("look at how *precise* the recorded time actually is",
   "the weakest part happens *before the cipher is ever called*") say the key was
   derived from the system time at encryption — a **time-seeded PRNG / time-derived key** —
   but the record truncates the timestamp to the minute.

## Solution

The real encryption time was **`2026-09-20T04:37:58Z` (epoch `1789879078`)** —
58 ticks past the recorded minute, i.e. "what was lost in the silence between two ticks".

```python
import base64, hashlib
from Crypto.Cipher import AES

ct    = base64.b64decode("/QuCUtzvX5n3x/c3OPyV4MAF7Y749Mjn4Q==")
nonce = bytes.fromhex("7e197b75b71d8956")
key   = hashlib.sha256(str(1789879078).encode()).digest()
# key = 7e197b75b71d8956ff5505aa94cb149ced47ad3179c2cb884b75476209dad08f
# key[:8] == nonce  ->  confirms the recovered seed is exact
flag = AES.new(key, AES.MODE_CTR, nonce=nonce).decrypt(ct)
print(flag.decode())   # Lun4r{t1m3_1s_n0t_4_prng}
```

## Recovery method

`brute_fast.py` swept the 60-second window at millisecond granularity, testing per
timestamp: `random.Random(seed).randbytes(16/24/32)`, `getrandbits(256)` (BE), the
glibc `srand/rand` stream, and `sha256/md5/sha1` of every string form of the time
(`str(t)`, ms/us/ns integers, `%.6f`), each against ChaCha20, Salsa20 and AES-CTR
(counter 0 and 1), with a printable-ASCII filter and a PRNG nonce-reproduction oracle.

The hit: **`key = sha256("1789879078")`, cipher AES-CTR**. The decisive confirmation is
that `key[:8]` equals the published nonce — the author generated the nonce from the key
itself, so the match can't be a false positive. The flag itself sums it up:
*time is not a PRNG*.

Note: the same-page brute force with ±30 s integer offsets (and `sha256(str(int))`)
missed it only because the true time sits +58 s from the minute mark.
