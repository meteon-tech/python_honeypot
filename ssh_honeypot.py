#!/usr/bin/python3
import asyncssh
import asyncio
import logging

LOG_SSH = 'honeypot_ssh_logs.csv'
HOST = '0.0.0.0'
PORT = 2222

logFormat = logging.Formatter('%(asctime)s,%(message)s', datefmt='%Y-%m-%d %H:%M:%S')

fileHandler = logging.FileHandler(LOG_SSH, mode='a', encoding='utf-8')
fileHandler.setFormatter(logFormat)

honeypotLogger = logging.getLogger('honeypotSSH')
honeypotLogger.setLevel(logging.INFO)
honeypotLogger.addHandler(fileHandler)

class Honeypot(asyncssh.SSHServer):
	def connection_made(self, conn):
		self._conn = conn
		peername = conn.get_extra_info('peername')

		self.ip = peername[0]
		self.port = peername[1]

	def password_auth_supported(self):
		return True

#	def kbdint_auth_supported(self):
#		return False

	def validate_password(self, username, password):
		print(f'Log in: {username}, {password}', flush=True)
		self.clientVersion = self._conn.get_extra_info('client_version')
		honeypotLogger.info(f"{self.ip},{self.port},{username},{password},{self.clientVersion}")
		return False



async def serverStart():
	key = asyncssh.generate_private_key('ssh-rsa')

	await asyncssh.create_server(
		Honeypot,
		host=HOST,
		port=PORT,
		server_host_keys=[key],
		password_auth=True,
		kbdint_auth=False
	)

	print(f'Honeypot is runing on: {HOST}:{PORT}')
	await asyncio.Future()

try:
	asyncio.run(serverStart())
except KeyboardInterrupt:
	print(f'SSH was stopped by user')
