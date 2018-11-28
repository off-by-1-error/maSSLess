from util import *

def rsa_pkcs1_v15_pad(m, nbytes):
    pslen = nbytes-len(m)-3
    ps = b""
    while len(ps) < pslen:
        b = getRandomBytes(1)
        if b != b"\0":
            ps += b
    return b"\x00\x02"+ps+b"\x00"+m

def rsa_pkcs1_v15_encrypt(m, key):
    n, e = key
    m = rsa_pkcs1_v15_pad(m, (n.bit_length()+7)//8)
    m = bytes_to_long(m)
    c = pow(m, e, n)
    c = long_to_bytes(c)
    return c
