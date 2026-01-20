import os
import csv
import logging
import datetime
from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

LOG_FILE = 'honeypot_ftp_logs.csv'
PORT = 2121
HOST = '0.0.0.0'

class MyAuthorizer(DummyAuthorizer):
	def validate_authentication(self, username, password, handler):
		ip = handler.remote_ip
		port = handler.remote_port

		print(ip, port, username, password)
		logCsv(datetime.datetime.now(), ip, port, username, password)
		raise AuthenticationFailed('Authentication failed')


def logCsv(timestamp, ip, port, username, password):
	row = [timestamp, ip, port, username, password]
	with open(LOG_FILE, 'a') as file:
		write = csv.writer(file)
		write.writerow(row)


authorizer = MyAuthorizer()

handler = FTPHandler
handler.authorizer = authorizer

handler.banner = 'Hello'

address = (HOST, PORT)
server = FTPServer(address, handler)

server.max_cons = 256
server.max_cons_per_ip = 5

server.serve_forever()
