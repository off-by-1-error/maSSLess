import sys, socket
from massless import *

host = "0"
port = 4433

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))
state = SSLState(sock, "client")

state.sendClientHello()
state.recvServerHandshake()
state.sendClientKeyExchange()
state.sendChangeCipherSpec()
state.sendFinished()

time.sleep(5)
