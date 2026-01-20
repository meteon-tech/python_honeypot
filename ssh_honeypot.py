#!/usr/bin/python3
import asyncssh
import asyncio
import csv
import datetime

class Honeypot(asyncssh.SSHServer):
	def connection_made(self, conn):
		self._conn = conn
		self.ip = conn.get_extra_info('peername')[0]
		print(f'Connection from: {self.ip}', flush=True)

	def password_auth_supported(self):
		return True

	def validate_password(self, username, password):
		print(f'This: {username}, {password}', flush=True)
		logCsvSsh(datetime.datetime.now(), self.ip, username, password)
		return False

LOG_SSH = 'honeypot_ssh_logs.csv'


def logCsvSsh(timestamp, ip, user, password):
	row = [timestamp, ip, user, password]
	try:
		with open(LOG_SSH, 'a') as file:
			write = csv.writer(file)
			write.writerow(row)
	except Exception as e:
		print(e)

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
