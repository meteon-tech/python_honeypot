#!/usr/bin/python3
import socket
import logging
import threading
import configparser

config = configparser.ConfigParser()
config.read('config.ini')

HOST = config.get('Telnet', 'Host', fallback='0.0.0.0')
TELNET_PORT = config.getint('Telnet', 'Port', fallback=2323)

LOG_FILE = 'honeypot_telnet_logs.csv' 
BANNER = b'Linux 3.10.14 armv7l\r\n\r\n# '
MAX_CONNECTIONS = config.getint('Telnet', 'Connections', fallback=10)
MAX_CONNECTION_SIZE = 4096


logFormat = logging.Formatter('%(asctime)s,%(message)s', datefmt='%Y-%m-%d %H:%M:%S')

honeypotFile = logging.FileHandler(LOG_FILE)
honeypotFile.setFormatter(logFormat)

honeypotLog = logging.getLogger('honeypotTelnet')
honeypotLog.setLevel(logging.INFO)
honeypotLog.addHandler(honeypotFile)


threadLimiter = threading.Semaphore(MAX_CONNECTIONS)

def handleClient(client, addr):
	ip = addr[0]
	port = addr[1]
	honeypotLog.info(f"Connection made from: {ip}:{port}")
	buffer = bytearray()
	sizeData = 0
	try:
		client.settimeout(30)
		client.send(BANNER)
		while True:
			data = client.recv(1024)

			if not data:
				break

			sizeData += len(data)
			if sizeData > MAX_CONNECTION_SIZE:
				break

			buffer.extend(data)
			#hledame jestli uzivatel neposlal telnet interrupt process Ctrl-c xff,xf4
			if b'\xff\xf4' in buffer:
				return

			while b'\n' in buffer:
				line, rest = buffer.split(b'\n', 1)
				buffer = bytearray(rest)

				line = line.replace(b'\r', b'')

				if line.startswith(b'\xff'):
					client.send(b'# ')
					continue

				command = line.decode(errors='replace').strip()

				if not command:
					client.send(b'# ')
					continue

				safeCommand = command.replace(',', ';').replace('\n', ' ').replace('\r', '')
				honeypotLog.info(f"{ip},{port},{safeCommand}")

				if command.lower() == 'exit':
					return
				elif command.lower() == 'whoami':
					client.send(b'root\r\n')
				elif command.lower() == 'ls':
					client.send(b'bin\tdev\tetc\thome\tlib\tproc\troot\ttmp\tvar\r\n')
				client.send(b'# ')
	except socket.timeout:
		honeypotLog.warning(f'Connection timed out {ip}')

	except ConnectionError:
		honeypotLog.warning(f'Connection lost with {ip}')
	except Exception as e:
		honeypotLog.error(f'Error handling the client {e}')
	finally:
		client.close()
		threadLimiter.release()


def main():

	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	server.bind((HOST, TELNET_PORT))
	server.listen(5)
	server.settimeout(1)

	print('Telnet started')
	print(f'Telnet honeypot is listening on: {HOST}:{TELNET_PORT}')
	try:
		while True:
			try:
				client, addr = server.accept()
				if threadLimiter.acquire(blocking=False):
					thread = threading.Thread(target=handleClient, args=(client, addr), daemon=True)
					thread.start()
				else:
					client.close()
			except socket.timeout:
				continue
	except KeyboardInterrupt:
		print('Telnet was stopped by user')
	finally:
		server.close()

main()
