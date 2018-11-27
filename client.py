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

time.sleep(5)
