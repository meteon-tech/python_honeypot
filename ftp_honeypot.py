#!/usr/bin/python3
import os
from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

class MyAuthorizer(DummyAuthorizer):
	def validate_authentication(self, username, password, handler):
		ip = handler.remote_ip
		port = handler.remote_port

		print(ip, port, username, password)

		raise AuthenticationFailed('Authentication failed')

authorizer = MyAuthorizer()

handler = FTPHandler
handler.authorizer = authorizer

handler.banner = 'Hello'

address = ('0.0.0.0', 2121)
server = FTPServer(address, handler)

server.max_cons = 256
server.max_cons_per_ip = 5

server.serve_forever()
