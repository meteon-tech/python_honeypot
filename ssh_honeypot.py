#!/usr/bin/python3
import asyncssh
import asyncio
import logging
import configparser

config = configparser.ConfigParser()
config.read('config.ini')

LOG_SSH = 'honeypot_ssh_logs.csv'
HOST = config.get('SSH', 'Host', fallback='0.0.0.0')
SSH_PORT = config.getint('SSH', 'Port', fallback=2222)

logFormat = logging.Formatter('%(asctime)s,%(message)s', datefmt='%Y-%m-%d %H:%M:%S')

honeypotFile = logging.FileHandler(LOG_SSH)
honeypotFile.setFormatter(logFormat)

honeypotLog = logging.getLogger('honeypotSSH')
honeypotLog.setLevel(logging.INFO)
honeypotLog.addHandler(honeypotFile)

class Honeypot(asyncssh.SSHServer):
	def connection_made(self, conn):
		self._conn = conn
		peername = conn.get_extra_info('peername')

		self.ip = peername[0]
		self.port = peername[1]

	def password_auth_supported(self):
		return True

	def validate_password(self, username, password):
		print(f'Log in: {username}, {password}')
		self.clientVersion = self._conn.get_extra_info('client_version')
		honeypotLog.info(f"{self.ip},{self.port},{username},{password},{self.clientVersion}")
		return False



async def serverStart():
	key = asyncssh.generate_private_key('ssh-rsa')

	await asyncssh.create_server(
		Honeypot,
		host=HOST,
		port=SSH_PORT,
		server_host_keys=[key],
		password_auth=True,
		kbdint_auth=False
	)

	print(f'SSH honeypot is runing on: {HOST}:{SSH_PORT}')
	await asyncio.Future()

try:
	asyncio.run(serverStart())
except KeyboardInterrupt:
	print(f'SSH was stopped by user')
