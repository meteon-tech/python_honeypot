#!/usr/bin/python3
import logging
import configparser
from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

config = configparser.ConfigParser()
config.read('config.ini')

LOG_FILE = 'honeypot_ftp_logs.csv'
FTP_PORT = config.getint('FTP', 'Port', fallback=2121)
HOST = config.get('FTP', 'Host', fallback='0.0.0.0')

logFormat = logging.Formatter('%(asctime)s,%(message)s', datefmt='%Y-%m-%d %H:%M:%S')

honeypotFile = logging.FileHandler(LOG_FILE)
honeypotFile.setFormatter(logFormat)


honeypotLog = logging.getLogger('honeypotFTP')
honeypotLog.setLevel(logging.INFO)
honeypotLog.addHandler(honeypotFile)


class MyAuthorizer(DummyAuthorizer):
	def validate_authentication(self, username, password, handler):
		ip = handler.remote_ip
		port = handler.remote_port

		honeypotLog.info(f"{ip},{port},{username},{password}")
		raise AuthenticationFailed('Authentication failed')


authorizer = MyAuthorizer()

handler = FTPHandler
handler.authorizer = authorizer

handler.banner = 'ProFTPD 1.3.5 Server (Debian)'

address = (HOST, FTP_PORT)
server = FTPServer(address, handler)

server.max_cons = config.getint('FTP', 'Connections', fallback=50)
server.max_cons_per_ip = 3

server.serve_forever()
