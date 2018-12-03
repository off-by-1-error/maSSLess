## Dependencies
requires `python3 >= 3.6` (`secrets` module introduced in 3.6)
asn1 parser: `pip3 install asn1`

## Testing
to generate your own key/cert to run a server, you can use `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes`  

to run a server or client with openssl (to test interacting with our client/server respectively):  
`openssl s_server --key key.pem --cert cert.pem` (default port 4433)  
`openssl s_client` (defaults to localhost:4433)  

and to run our server or client:
`python3 server.py --key key.pem --cert cert.pem`  
`python3 client.py localhost 4433`
