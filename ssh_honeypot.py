#!/usr/bin/python3
import asyncssh
import asyncio
import logging

LOG_SSH = 'honeypot_ssh_logs.csv'

logFormat = logging.Formatter('%(asctime)s,%(message)s', datefmt='%Y-%m-%d %H:%M:%S')

fileHandler = logging.FileHandler(LOG_SSH, mode='a', encoding='utf-8')
fileHandler.setFormatter(logFormat)

honeypotLogger = logging.getLogger('honeypotSSH')
honeypotLogger.setLevel(logging.INFO)
honeypotLogger.addHandler(fileHandler)

class Honeypot(asyncssh.SSHServer):
	def connection_made(self, conn):
		self._conn = conn
		self.ip = conn.get_extra_info('peername')[0]
		print(f'Connection from: {self.ip}', flush=True)

	def password_auth_supported(self):
		return True

	def validate_password(self, username, password):
		print(f'Log in: {username}, {password}', flush=True)

		honeypotLogger.info(f"{self.ip},{username},{password}")
		return False



async def serverStart():
	key = asyncssh.generate_private_key('ssh-rsa')

	await asyncssh.create_server(
		Honeypot,
		host='0.0.0.0',
		port=2222,
		server_host_keys=[key],
		password_auth=True,
	)

	print('Honeypot is runing on port 2222')
	await asyncio.Future()

try:
	asyncio.run(serverStart())
except KeyboardInterrupt:
	print(f'Honeypot is shutting down')
