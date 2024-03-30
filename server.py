#!/usr/bin/env python3

from socketserver import BaseRequestHandler, UDPServer

class UdpHanlder(BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        print("{} wrote:".format(self.client_address[0]))
        print(data)

if __name__ == "__main__":
    HOST, PORT = "localhost", 9995
    with UDPServer((HOST, PORT), UdpHanlder) as server:
        server.serve_forever()
