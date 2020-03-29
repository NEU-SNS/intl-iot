import socket
import os
import sys

if len(sys.argv) < 3:
    print('usage: %s input-file 1/0' % sys.argv[0])
    print('\t1:encryted')
    print('\t0:not encryted')
    exit(0)
inputfile = sys.argv[1]
is_enc = sys.argv[2]

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # print("Socket successfully created")
except socket.error as err:
    print("socket creation failed with error %s" % (err))

enc_port = 12345
plain_port = 12346
video_port = 12347
venc_port = 12348
ssl_port = 8443

# default port for socket
if is_enc == '1' :
    port = enc_port
elif is_enc == '0':
    port = plain_port
elif is_enc == 've': # video encrypted
    port = venc_port
elif is_enc == 'vp': # vidoe plain
    port = video_port

host = 'localhost'

data = open(inputfile, 'rb').read()

try:
    host_ip = socket.gethostbyname(host)
except socket.gaierror:
    # this means could not resolve the host
    print("there was an error resolving the host")
    sys.exit()

# connecting to the server
s.connect((host_ip, port))
s.sendall(data)
received = str(s.recv(1024))
s.close()
# print("the socket has successfully connected to %s on port == %s" % (host, host_ip))
print('Sending content of %s to port %s' % (inputfile, port))
print("\tReceived: {}".format(received))
