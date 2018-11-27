from enum import Enum
from util import *
import asn1

DEF_VERSION = (3,3)

class RecordType(Enum):
    CHANGE_CIPHER_SPEC = 0x14
    ALERT = 0x15
    HANDSHAKE = 0x16
    APPLICATION = 0x17

class HandshakeType(Enum):
    HELLO_REQ = 0
    CLIENT_HELLO = 1
    SERV_HELLO = 2
    NEW_SESSION_TICKET = 4
    ENC_EXTENSIONS = 8
    CERT = 11
    SERV_KEY_EXCHANGE = 12
    CERT_REQ = 13
    SERV_HELLO_DONE = 14
    CERT_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FIN = 20

class CompressionType(Enum):
    NULL = 0

class CipherSuite(Enum):
    #TLS_DH_anon_WITH_AES_128_CBC_SHA = 0x34
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x35

class KeyExchangeAlgo(Enum):
    RSA = 0
    DHE_DSS = 1
    DHE_RSA = 2
    DH_DSS = 3
    DH_RSA = 4
    DH_ANON = 5

# https://tools.ietf.org/html/rfc5246
class SSLState():
    def __init__(self, sock, end, version=DEF_VERSION):
        self.version = version
        self.sock = sock
        if end not in ["server", "client"]:
            raise Exception("connection end must be either \"server\" or \"client\"")
        self.end = end
        self.serv_done = False
        self.handshake_messages = b""

    def send(self, pl):
        self.sock.sendall(pl)
    def recv(self, n):
        ret = b""
        while len(ret) < n:
            ret += self.sock.recv(n-len(ret))
        return ret

    def getRandom(self):
        return p32(getTimestamp())+getRandomBytes(28)

    def getCipherSuites(self):
        return (c.value for c in CipherSuite)
    def getRawCipherSuites(self):
        cc = b"".join(p16(c) for c in self.getCipherSuites())
        return p16(len(cc))+cc

    def sendTlsRecord(self, typ, pl):
        '''
        create raw format for tls record
        typ: RecordType enum
        pl: message payload as raw bytes
        version: tuple of tls version
        '''
        self.send(p8(typ.value, self.version[0], self.version[1])+p16(len(pl))+pl)

    def sendHandshake(self, *args):
        '''
        creates raw format for a handshake record
        called with either (typ, pl) where typ is a HandshakeType enum, pl is the raw bytes
          or with an iterable producing tuples of that type
          to pack multiple handshakes messages into a single record
          i.e. ((typ0,pl0),(typ1,pl1))
        '''
        msgs = (args,) if len(args) == 2 else args
        pl = b"".join(p8(m[0].value)+p24(len(m[1]))+m[1] for m in msgs)
        self.handshake_messages += pl # assuming no HelloRequests are in here
        self.sendTlsRecord(RecordType.HANDSHAKE, pl)

    def sendHelloReq(self):
        self.sendHandshake(HandshakeType.HELLO_REQ, b"")

    def sendClientHello(self):
        '''
        send a client hello handshake message
        generates and stores a client.random
        no sessions or extensions
        '''
        self.client_random = self.getRandom()
        pl = p8(*self.version)
        pl += self.client_random
        pl += p8(0) # session id length
        pl += self.getRawCipherSuites()
        pl += p8(1, CompressionType.NULL.value) # compression methods
        pl += p16(0) # extensions length
        self.sendHandshake(HandshakeType.CLIENT_HELLO, pl)

    def sendServerHello(self):
        '''
        send a server hello handshake message
        no sessions or extensions
        '''
        self.server_random = self.getRandom()
        pl = p8(*self.version)
        pl += p8(0) # session id length
        pl += p16(self.cipher_suite.value)
        pl += p8(CompressionType.NULL.value) # compression method null
        self.sendHandshake(HandshakeType.SERVER_HELLO, pl)

    def sendChangeCipherSpec(self):
        #self.master = self.prf(self.premaster, b"master secret", self.client_random+self.server_random)[:48]
        del self.premaster
        self.sendTlsRecord(RecordType.CHANGE_CIPHER_SPEC, b"\x01")

    def parseServerHello(self, data):
        i = 0
        version = data[i:i+2] ; i += 2
        self.server_random = data[i:i+32] ; i += 32
        sess_len = u8(data[i:i+1]) ; i += 1
        self.session_id = data[i:i+sess_len] ; i += sess_len
        self.cipher_suite = CipherSuite(u16(data[i:i+2])) ; i += 2
        self.compression = CompressionType(u8(data[i:i+1])) ; i += 1

    def parseServerCert(self, data):
        # if theres a good way to do this, please do
        cert_len = u24(data[3:6]) # only care about first cert with pubkey
        cert = data[6:6+cert_len]
        decoder = asn1.Decoder()
        decoder.start(cert)
        decoder.enter()
        decoder.enter()
        for i in range(6):
            decoder.read()
        decoder.enter()
        decoder.read()
        tag, val = decoder.read()
        decoder.start(val[1:]) # unused byte what??
        decoder.enter()
        tag, n = decoder.read()
        tag, e = decoder.read()
        self.serv_rsa_key = (n,e)

    def recvServerHandshake(self):
        while not self.serv_done:
            typ = u8(self.recv(1))
            if typ != RecordType.HANDSHAKE.value:
                raise Exception("expected Handshake message got %s"%RecordType(typ))
            version = self.recv(2) # need to check this?
            data_len = u16(self.recv(2))
            while data_len > 0:
                op = HandshakeType(u8(self.recv(1)))
                op_len = u24(self.recv(3))
                data = self.recv(op_len)
                data_len -= 4+op_len
                if op == HandshakeType.SERV_HELLO:
                    self.parseServerHello(data)
                elif op == HandshakeType.CERT:
                    self.parseServerCert(data)
                elif op == HandshakeType.SERV_KEY_EXCHANGE:
                    raise Exception("not implemented")
                elif op == HandshakeType.CERT_REQ:
                    raise Exception("not implemented")
                elif op == HandshakeType.SERV_HELLO_DONE:
                    self.serv_done = True
                else:
                    raise Exception("unexpected message receiving server handshake: %s"%op)

    def sendClientKeyExchange(self):
        self.premaster = p8(*self.version)+getRandomBytes(46)
        # TODO: i have no idea what the padding scheme is if any o.0
        n, e = self.serv_rsa_key
        enc = long_to_bytes(pow(bytes_to_long(self.premaster), e, n))
        pl = p16(len(enc))+enc
        self.sendHandshake(HandshakeType.CLIENT_KEY_EXCHANGE, pl)

    def sendFinished(self):
        #TODO
        # need to send prf(master, "client/server finished", H(handshake_messages))
        # ... need sha256 for prf
        pass
