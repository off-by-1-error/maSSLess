## Dependencies
requires `python3 >= 3.6` (`secrets` module introduced in 3.6)
asn1 parser: `pip3 install asn1`

## Testing
to generate your own key/cert to run a server, you can use `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes`
