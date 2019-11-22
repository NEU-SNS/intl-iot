import socket
import ssl
import sys

if len(sys.argv) < 2:
    exit(0)

SELECTED_CIPHER = sys.argv[1]

hostname = '127.0.0.1'

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

context.set_ciphers(SELECTED_CIPHER)
context.load_cert_chain('device.pem', 'device.key')


def deal_with_client(connstream):

    data = connstream.recv(1024)
    while data:
        print("Received: %s " % len(data))
        data = connstream.recv(1024)



with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind((hostname, 8443))
    sock.listen(5)
    with context.wrap_socket(sock, server_side=True) as ssock:
        conn, addr = ssock.accept()
        # print(conn.shared_ciphers())
        print(conn.cipher())
        deal_with_client(conn)
        print('---------\n')
    sock.close()
