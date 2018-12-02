import struct, time, secrets
from crypto import sha1, sha256

def p64(*args):
    return b"".join(struct.pack("!Q", x) for x in args)
def u64(x):
    return struct.unpack("!Q", x)[0]
def p32(*args):
    return b"".join(struct.pack("!I", x) for x in args)
def u32(x):
    return struct.unpack("!I", x)[0]
def p16(*args):
    return b"".join(struct.pack("!H", x) for x in args)
def u16(x):
    return struct.unpack("!H", x)[0]
def p8(*args):
    return b"".join(struct.pack("!B", x) for x in args)
def u8(x):
    return struct.unpack("!B", x)[0]
def p24(x):
    if x >= 0x1000000:
        raise Exception("argument to p24 (0x%x) exceeds maximum of 0xffffff"%x)
    return struct.pack("!I", x)[1:]
def u24(x):
    if len(x) != 3:
        raise Exception("argument to u24 must be 3 bytes (was %d bytes)"%len(x))
    return struct.unpack("!I", b"\0"+x)[0]
def bytes_to_long(x):
    return int.from_bytes(x, "big")
def long_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, "big")

def getTimestamp():
    return int(time.time())

def getRandomBytes(n):
    return secrets.token_bytes(n)

def xor(a, b):
    if len(a) != len(b):
        raise Exception("trying to xor different length strings")
    return b"".join(bytes([a[i]^b[i]]) for i in range(len(a)))

# credit for modinv goes to stackoverflow
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def computeHmac(k, m, blocksize, h):
    if len(k) > blocksize:
        k = h(k)
    k += b"\0"*(blocksize-len(k))
    inner = xor(k, b"\x36"*blocksize)+m
    inner = h(inner)
    outer = xor(k, b"\x5c"*blocksize)+inner
    outer = h(outer)
    return outer

def compute_sha256(m):
    return sha256.sha256(m)
def hmac_sha256(k, m):
    return computeHmac(k, m, 64, compute_sha256)
def compute_sha1(m):
    return sha1.sha1(m)
def hmac_sha1(k, m):
    return computeHmac(k, m, 64, compute_sha1)
