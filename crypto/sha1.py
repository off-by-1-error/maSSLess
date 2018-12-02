import struct

def p64(*args):
    return b"".join(struct.pack("!Q", x) for x in args)
def u64(x):
    return struct.unpack("!Q", x)[0]
def p32(*args):
    return b"".join(struct.pack("!I", x) for x in args)
def u32(x):
    return struct.unpack("!I", x)[0]


def left_rotate(num, bits):
    return ((num << bits) | (num >> (32 - bits))) & 0xffffffff


def sha1(msg):
    """
    will return sha1 hash of data
    """

    #Pre-processing
    #calc padding
    padding = b"\x80" + b"\x00" * (55 - len(msg) % 64)
    if len(msg) % 64 > 55:
        padding += b"\x00" * (64 + 55 - len(msg) % 64)

    padded_msg = msg + padding + p64(len(msg) * 8)

    #define start
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    #break into chunks
    tmp = padded_msg
    chunks = []
    while len(tmp) > 0:
        chunks.append(tmp[:64])
        tmp = tmp[64:]


    for chunk in chunks:
        w = [0] * 80
        for i in range(16):
            w[i] = u32(chunk[i*4:i*4 + 4])

        for i in range(16, 80):
            w[i] = left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for i in range(80):
            if 0 <= i <= 19:
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            temp = (left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff
            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = temp

        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    #calculate final value
    return p32(h0) + p32(h1) + p32(h2) + p32(h3) + p32(h4)
