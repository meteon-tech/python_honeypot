#!/usr/bin/python3
import asyncssh
import asyncio
import logging
import configparser
import sys
import ipaddress

config = configparser.ConfigParser()
config.read('config.ini')

LOG_SSH = 'honeypot_ssh_logs.csv'

try:
	HOST = config.get('SSH', 'Host', fallback='0.0.0.0')
	SSH_PORT = config.getint('SSH', 'Port', fallback=2222)

	ipaddress.ip_address(HOST)

	if SSH_PORT > 65535 or SSH_PORT < 1:
		raise ValueError('Port is out of range')

except Exception as e:
	print(f'Wrong configuration format: {e}')
	sys.exit()

logFormat = logging.Formatter('%(asctime)s,%(message)s', datefmt='%Y-%m-%d %H:%M:%S')

honeypotFile = logging.FileHandler(LOG_SSH)
honeypotFile.setFormatter(logFormat)

honeypotLog = logging.getLogger('honeypotSSH')
honeypotLog.setLevel(logging.INFO)
honeypotLog.addHandler(honeypotFile)


#vytvorim si vlastni tridu do pro overovani uzivatelu a
#do ni zdedim vse z tridy sshserver
class Honeypot(asyncssh.SSHServer):
	def connection_made(self, conn):
		self._conn = conn
		peername = conn.get_extra_info('peername')

		self.ip = peername[0]
		self.port = peername[1]

	def password_auth_supported(self):
		return True


	#upravim si metodu validate_password
	def validate_password(self, username, password):
		print(f'Log in user: {username}')
		self.clientVersion = self._conn.get_extra_info('client_version')
		honeypotLog.info(f"{self.ip},{self.port},{username},{password},{self.clientVersion}")
		#pokazde vratim False, aby se utocnik nemohl prihlasit
		return False



async def serverStart():
	key = asyncssh.generate_private_key('ssh-rsa')
	try:

		await asyncssh.create_server(
			Honeypot,
			host=HOST,
			port=SSH_PORT,
			server_host_keys=[key],
			password_auth=True,
			kbdint_auth=False
		)
	except:
		print('Wrong ip address or port on interface')
		sys.exit()

	print(f'SSH honeypot is running on: {HOST}:{SSH_PORT}')
	await asyncio.Future()

try:
	asyncio.run(serverStart())
except KeyboardInterrupt:
	print(f'SSH was stopped by user')
