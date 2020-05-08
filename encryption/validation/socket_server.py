"""

Modified from https://docs.python.org/3.4/library/socketserver.html
"""
import socketserver
import sys

class MyTCPHandler(socketserver.BaseRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def handle(self):
        # self.request is the TCP socket connected to the client
        self.data = self.request.recv(1500)#.strip()
        print("{} wrote:".format(self.client_address[0]))
        # print(self.data)
        # just send back the same data, but upper-cased
        self.request.sendall('%d received'%len(self.data))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Specify the port - python %s 12345/12346' % sys.argv[0])
        exit(0)
    HOST, PORT = "localhost", int(sys.argv[1])
    print('Running socket server at port %s' %  PORT)
    # Create the server, binding to localhost on port
    server = socketserver.TCPServer((HOST, PORT), MyTCPHandler)

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    server.serve_forever()