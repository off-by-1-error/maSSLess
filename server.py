import sys, socket, argparse
from massless import *

parser = argparse.ArgumentParser(description="run simple ssl server")
parser.add_argument("--key", help="private key file in pem format", required=True)
parser.add_argument("--cert", help="cert file in pem format", required=True)
parser.add_argument("-p", "--port", help="port to bind to", type=int, default=4433)
args = parser.parse_args()

state = SSLState(None, "server")
state.readServerPrivkey(args.key)
state.readServerCert(args.cert)

host = "0"
port = args.port

serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
serv.bind((host, port))
serv.listen(32)
sock = serv.accept()[0]
state.sock = sock

state.recvClientHandshake()
state.recvFinished()
state.sendChangeCipherSpec()
state.sendFinished()

state.send(b"ping\n")
out = state.recv()
print(out.decode("raw_unicode_escape"))
