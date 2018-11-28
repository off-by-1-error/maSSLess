import sys, socket
from massless import *

host = "google.com"
port = 443

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))
state = SSLState(sock, "client")

state.sendClientHello()
state.recvServerHandshake()
state.sendClientKeyExchange()
state.sendChangeCipherSpec()
state.sendFinished()

state.recvChangeCipherSpec()
state.recvFinished()

state.send(b"GET /\n")
while True:
    out = state.recv()
    sys.stdout.write(out.decode("ISO-8859-1"))
