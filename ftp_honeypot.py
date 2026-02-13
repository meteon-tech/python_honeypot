#!/usr/bin/python3
import logging
import configparser
from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

config = configparser.ConfigParser()
config.read('config.ini')

LOG_FILE = 'honeypot_ftp_logs.csv'
FTP_PORT = config.getint('FTP', 'Port')
HOST = config.get('FTP', 'Host')

honeypotLogger = logging.getLogger('honeypotFtp')
honeypotLogger.setLevel(logging.INFO)

logFormat = logging.Formatter('%(asctime)s,%(message)s', datefmt='%Y-%m-%d %H:%M:%S')

fileHandler = logging.FileHandler(LOG_FILE, mode='a', encoding='utf-8')
fileHandler.setFormatter(logFormat)
honeypotLogger.addHandler(fileHandler)


class MyAuthorizer(DummyAuthorizer):
	def validate_authentication(self, username, password, handler):
		ip = handler.remote_ip
		port = handler.remote_port

		honeypotLogger.info(f"{ip},{port},{username},{password}")
		raise AuthenticationFailed('Authentication failed')


authorizer = MyAuthorizer()

handler = FTPHandler
handler.authorizer = authorizer

handler.banner = 'ProFTPD 1.3.5 Server (Debian)'

address = (HOST, FTP_PORT)
server = FTPServer(address, handler)

server.max_cons = 50
server.max_cons_per_ip = 3

server.serve_forever()
