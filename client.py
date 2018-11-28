import sys, socket, argparse
from massless import *

parser = argparse.ArgumentParser(description="run simple ssl client")
parser.add_argument("host", help="server to connect to")
parser.add_argument("port", help="port to connect to", type=int)
args = parser.parse_args()

host = args.host
port = args.port

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

inp = sys.stdin.readline() # for google.com:443, input 'GET /'
state.send(inp.encode("utf-8"))
while True:
    try:
        out = state.recv()
        sys.stdout.write(out.decode("raw_unicode_escape"))
    except TypeError: # eof
        break
