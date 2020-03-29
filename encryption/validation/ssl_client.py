import socket
import ssl
import sys

hostname = '127.0.0.1'
if len(sys.argv) < 2:
    exit(0)
inputfile = sys.argv[1]
print('\tRead file %s' % inputfile)
# msg = b"HEAD / HTTP /1.0\r\nHost: linuxfr.org\r\n\r\n"
msg = open(inputfile).read()
msg = bytes(msg.encode())

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations('rootCA.pem')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        ssock.connect((hostname, 8443))
        # cert = ssock.getpeercert()

        ssock.sendall(msg)
        print('\tSent %s .+' % msg[:10])
