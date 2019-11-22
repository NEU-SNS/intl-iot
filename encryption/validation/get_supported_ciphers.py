import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ciphers = context.get_ciphers()
for c in ciphers:
    print('%s' % c['name'])