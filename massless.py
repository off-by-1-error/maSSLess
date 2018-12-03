from enum import Enum
from util import *
from crypto import rsa, sha256
import asn1, base64

DEF_VERSION = (3,3)

class RecordType(Enum):
    CHANGE_CIPHER_SPEC = 0x14
    ALERT = 0x15
    HANDSHAKE = 0x16
    APP = 0x17

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
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x2f
    #TLS_DH_anon_WITH_AES_128_CBC_SHA = 0x34

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
        self.client_done = False
        self.handshake_messages = b""
        self.prf = self.tls_prf_sha256

    def send_raw(self, pl):
        self.sock.sendall(pl)
    def recv_raw(self, n):
        ret = b""
        while len(ret) < n:
            ret += self.sock.recv(n-len(ret))
            if len(ret) == 0:
                return None
        return ret

    def computeMasterSecret(self):
        rands = self.client_random + self.server_random
        self.master = self.prf(self.premaster, b"master secret", rands, 48)
        del self.premaster
    def computeSharedKeys(self):
        rands = self.server_random + self.client_random
        # right now, only support TLS_RSA_WITH_AES_128_CBC_SHA
        # so mac keys are 20 bytes, keys/ivs 16 bytes
        kdata = self.prf(self.master, b"key expansion", rands, 20*2+16*2)
        i = 0
        self.cli_mac_key = kdata[i:i+20] ; i += 20
        self.serv_mac_key = kdata[i:i+20] ; i += 20
        self.cli_key = kdata[i:i+16] ; i += 16
        self.serv_key = kdata[i:i+16] ; i += 16
        self.m_key, self.peer_key = self.serv_key, self.cli_key
        self.m_mac_key, self.peer_mac_key = self.serv_mac_key, self.cli_mac_key
        if self.end == "client":
            self.m_key, self.peer_key = self.peer_key, self.m_key
            self.m_mac_key, self.peer_mac_key = self.peer_mac_key, self.m_mac_key

    def readServerPrivkey(self, fname):
        raw = open(fname, "rb").read()
        raw = b"\n".join(l for l in raw.split(b'\n') if b"-----" not in l)
        raw = base64.b64decode(raw)
        decoder = asn1.Decoder()
        decoder.start(raw)
        decoder.enter()
        decoder.read()
        decoder.read()
        tag, val = decoder.read()
        decoder.start(val)
        decoder.enter()
        decoder.read()
        tag, n = decoder.read()
        tag, e = decoder.read()
        decoder.read()
        tag, p = decoder.read()
        tag, q = decoder.read()
        if p*q != n:
            raise Exception("rsa private key factors incorrect")
        phi = (p-1)*(q-1)
        d = modinv(e, phi)
        self.serv_rsa_privkey = (d, n)
        self.serv_rsa_pubkey = (n, e)
    def readServerCert(self, fname):
        raw = open(fname, "rb").read()
        raw = b"\n".join(l for l in raw.split(b'\n') if b"-----" not in l)
        raw = base64.b64decode(raw)
        self.serv_cert = raw

    def getRandom(self):
        return p32(getTimestamp())+getRandomBytes(28)

    def tls_prf_sha256(self, secret, label, seed, nbytes):
        seed = label + seed
        aa = seed
        out = b""
        while len(out) < nbytes:
            aa = hmac_sha256(secret, aa)
            out += hmac_sha256(secret, aa+seed)
        return out[:nbytes]

    def encryptData(self, typ, version, data):
        macced = p64(self.m_seq)+p8(typ.value)+version+p16(len(data))+data
        self.m_seq += 1
        pl = data
        pl += hmac_sha1(self.m_mac_key, macced)
        plen = 16 - (len(pl) % 16)
        pl += p8(plen-1)*plen
        #from Crypto.Cipher import AES #TODO: insert our aes
        #iv = getRandomBytes(16)
        #aes = AES.new(self.m_key, AES.MODE_CBC, iv)
        #enc = aes.encrypt(pl)
        #enc = iv + enc

        enc = aes_cbc_encrypt(self.m_key, pl)
        return enc
    def decryptData(self, enc):
        #iv = enc[:16]
        #enc = enc[16:]
        #from Crypto.Cipher import AES #TODO: insert our aes
        #aes = AES.new(self.peer_key, AES.MODE_CBC, iv)
        #msg = aes.decrypt(enc)
        aes_cbc_decrypt(self.peer_key, enc)
        return msg
    def verifyMsg(self, typ, version, msg):
        # TODO: this just doesnt work.... mac not correct
        padlen = u8(bytes([msg[-1]]))
        if msg[-padlen-1:-1] != bytes([padlen])*padlen:
            raise Exception("bad padding") #TODO: make sure this cant cause padding oracle attack
        mac = msg[-padlen-1-20:-padlen-1]
        content = msg[:-padlen-1-20]
        macced = p64(self.peer_seq)+p8(typ.value)+version+p16(len(content))+content
        self.peer_seq += 1
        m_mac = hmac_sha1(self.peer_mac_key, macced)
        if m_mac != mac:
            raise Exception("bad mac")
        return content

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
        self.send_raw(p8(typ.value, self.version[0], self.version[1])+p16(len(pl))+pl)

    def buildRawHandshake(self, typ, pl):
        return p8(typ.value)+p24(len(pl))+pl

    def sendHandshake(self, *args):
        '''
        creates raw format for a handshake record
        called with either (typ, pl) where typ is a HandshakeType enum, pl is the raw bytes
          or with an iterable producing tuples of that type
          to pack multiple handshakes messages into a single record
          i.e. ((typ0,pl0),(typ1,pl1))
        '''
        msgs = (args,) if len(args) == 2 else args
        pl = b"".join(self.buildRawHandshake(m[0], m[1]) for m in msgs)
        no_hellos = b"".join(self.buildRawHandshake(m[0], m[1]) for m in msgs if m[0] != HandshakeType.HELLO_REQ)
        self.handshake_messages += no_hellos
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
        pl += self.server_random
        pl += p8(0) # session id length
        pl += p16(self.cipher_suite.value)
        pl += p8(CompressionType.NULL.value) # compression method null
        self.sendHandshake(HandshakeType.SERV_HELLO, pl)

    def sendChangeCipherSpec(self):
        if self.end == "client":
            self.computeMasterSecret()
            self.computeSharedKeys()
        self.m_seq = 0
        self.sendTlsRecord(RecordType.CHANGE_CIPHER_SPEC, b"\x01")

    def recvChangeCipherSpec(self):
        typ = RecordType(u8(self.recv_raw(1)))
        if typ != RecordType.CHANGE_CIPHER_SPEC:
            raise Exception("expected ChangeCipherSpec got %s"%typ)
        version = self.recv_raw(2)
        data_len = u16(self.recv_raw(2))
        data = self.recv_raw(data_len)
        self.peer_seq = 0

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
        self.serv_rsa_pubkey = (n,e)

    def recvServerHandshake(self):
        while not self.serv_done:
            typ = u8(self.recv_raw(1))
            if typ != RecordType.HANDSHAKE.value:
                raise Exception("expected Handshake message got %s"%RecordType(typ))
            version = self.recv_raw(2) # need to check this?
            data_len = u16(self.recv_raw(2))
            while data_len > 0:
                op = HandshakeType(u8(self.recv_raw(1)))
                op_len = u24(self.recv_raw(3))
                data = self.recv_raw(op_len)
                data_len -= 4+op_len
                if op != HandshakeType.HELLO_REQ:
                    self.handshake_messages += p8(op.value)+p24(op_len)+data
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

    def parseClientHello(self, data):
        i = 0
        version = data[i:i+2] ; i += 2
        self.client_random = data[i:i+32] ; i += 32
        #TODO should parse the rest of the message
        self.cipher_suite = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA

    def recvClientHandshake(self):
        while not self.client_done:
            typ = u8(self.recv_raw(1))
            if typ == RecordType.CHANGE_CIPHER_SPEC.value:
                self.client_done = True
                version = self.recv_raw(2) # need to check this?
                data_len = u16(self.recv_raw(2))
                self.recv_raw(data_len)
                self.computeMasterSecret()
                self.computeSharedKeys()
                self.peer_seq = 0
                break
            elif typ != RecordType.HANDSHAKE.value:
                raise Exception("expected Handshake message got %s"%RecordType(typ))
            version = self.recv_raw(2) # need to check this?
            data_len = u16(self.recv_raw(2))
            while data_len > 0:
                op = HandshakeType(u8(self.recv_raw(1)))
                op_len = u24(self.recv_raw(3))
                data = self.recv_raw(op_len)
                data_len -= 4+op_len
                if op != HandshakeType.HELLO_REQ:
                    self.handshake_messages += p8(op.value)+p24(op_len)+data
                if op == HandshakeType.CLIENT_HELLO:
                    self.parseClientHello(data)
                    self.sendServerHello()
                    self.sendServerCert()
                    self.sendServerDone()
                elif op == HandshakeType.CLIENT_KEY_EXCHANGE:
                    #put parse leu exchange here
                    self.parseClientKeyExchange(data)

    def recvFinished(self):
        typ = RecordType(u8(self.recv_raw(1)))
        if typ != RecordType.HANDSHAKE:
            raise Exception("expected encrypted handshake finished message, got %s"%typ)
        version = self.recv_raw(2)
        data_len = u16(self.recv_raw(2))
        enc = self.recv_raw(data_len)
        msg = self.decryptData(enc)
        msg = self.verifyMsg(typ, version, msg)
        if msg[0] != HandshakeType.FIN.value:
            raise Exception("expected Finished message, got %s"%HandshakeType(u8(msg[0:1])))
        if u24(msg[1:4]) != len(msg)-4:
            raise Exception("length mismatch for Finished message")
        peer_verify = msg[4:]
        lbl = b"client finished" if self.end == "server" else b"server finished"
        verify = self.prf(self.master, lbl, sha256.sha256(self.handshake_messages), 12)
        if verify != peer_verify:
            raise Exception("verification of Finished message failed")
        if self.end == "server":
            self.handshake_messages += msg
        else:
            del self.handshake_messages

    def sendServerCert(self):
        pl = self.serv_cert
        pl = p24(len(pl))+pl
        pl = p24(len(pl))+pl
        self.sendHandshake(HandshakeType.CERT, pl)

    def sendServerDone(self):
        self.sendHandshake(HandshakeType.SERV_HELLO_DONE, b"")

    def sendClientKeyExchange(self):
        self.premaster = p8(*self.version)+getRandomBytes(46)
        enc = rsa.rsa_pkcs1_v15_encrypt(self.premaster, self.serv_rsa_pubkey)
        pl = p16(len(enc))+enc
        self.sendHandshake(HandshakeType.CLIENT_KEY_EXCHANGE, pl)
    
    def parseClientKeyExchange(self, data):
        enclen = u16(data[:2])
        enc = data[2:2+enclen]
        self.premaster = rsa.rsa_pkcs1_v15_decrypt(enc, self.serv_rsa_privkey)

    def sendFinished(self):
        #TODO
        # need to send prf(master, "client/server finished", H(handshake_messages))
        # ... need sha256 for prf
        from hashlib import sha256 #TODO implement sha
        lbl = b"client finished" if self.end == "client" else b"server finished"
        verify = self.prf(self.master, lbl, sha256(self.handshake_messages).digest(), 12)
        content = self.buildRawHandshake(HandshakeType.FIN, verify)
        if self.end == "client":
            self.handshake_messages += content
        else:
            del self.handshake_messages
        pl = self.encryptData(RecordType.HANDSHAKE, p8(*self.version), content)
        self.sendTlsRecord(RecordType.HANDSHAKE, pl)

    def send(self, msg):
        pl = self.encryptData(RecordType.APP, p8(*self.version), msg)
        self.sendTlsRecord(RecordType.APP, pl)
    def recv(self):
        typ = RecordType(u8(self.recv_raw(1)))
        if typ != RecordType.APP:
            raise Exception("expected to receive application data, got %s"%typ)
        version = self.recv_raw(2)
        data_len = u16(self.recv_raw(2))
        enc = self.recv_raw(data_len)
        msg = self.decryptData(enc)
        msg = self.verifyMsg(typ, version, msg)
        return msg
