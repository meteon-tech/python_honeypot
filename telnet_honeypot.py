#!/usr/bin/python3
import socket
import logging
import datetime
import threading

HOST = '0.0.0.0'
PORT = 2323
LOG_FILE = 'honeypot_telnet_logs.csv' 
BANNER = b'Linux 3.10.14 armv7l\r\n\r\n# '
MAX_CONNECTIONS = 2
MAX_CONNECTION_SIZE = 4096

threadLimiter = threading.Semaphore(MAX_CONNECTIONS)

def handleClient(client, addr):
	ip = addr[0]
	port = addr[1]
	logging.info(f"Connection made from: {ip}:{port}")
	buffer = bytearray()
	size = 0
	try:
		client.settimeout(30)
		client.send(BANNER)
		while True:
			data = client.recv(1024)
			print(data.hex())
			if not data:
				break
			print(data)

			size += len(data)
			if size > MAX_CONNECTION_SIZE:
				break

			buffer.extend(data)

			if b'\xff\xf4' in buffer:
				return

			while b'\n' in buffer:

				line, buffer = buffer.split(b'\n', 1)

				line = line.replace(b'\r', b'')

				if line.startswith(b'\xff'):
					client.send(b'# ')
					continue

				command = line.decode(errors='replace').strip()
				#if command.startswith('\xff'):
				#	return

				#command = data.decode(errors='ignore').strip()

				if not command:
					client.send(b'# ')
					continue
				logging.info(f"{ip},{port},{command}")
				if command.lower() == 'exit':
					return
				elif command.lower() == 'whoami':
					client.send(b'root\r\n')
				elif command.lower() == 'ls':
					client.send(b'bin\tdev\tetc\thome\tlib\tproc\troot\ttmp\tvar\r\n')
				client.send(b'# ')
	except socket.timeout:
		pass
	except Exception as e:
		print(e)
	finally:
		print('finnaly')
		client.close()
		threadLimiter.release()


def main():
	logFormat = logging.Formatter('%(asctime)s,%(message)s', datefmt='%Y-%m-%d %H:%M:%S')

	fileHandler = logging.FileHandler(LOG_FILE, mode='a', encoding='utf-8')
	fileHandler.setFormatter(logFormat)

	logger = logging.getLogger()
	logger.setLevel(logging.INFO)
	logger.addHandler(fileHandler)

	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	server.bind((HOST, PORT))
	server.listen(5)
	server.settimeout(1)

	try:
		while True:
			try:
				client, addr = server.accept()
				if threadLimiter.acquire(blocking=False):
					thread = threading.Thread(target=handleClient, args=(client, addr))
					thread.daemon = True
					thread.start()
				else:
					print('connection refused')
					client.close()
			except socket.timeout:
				continue
	except KeyboardInterrupt:
		print('Telnet was stopped by user')
	finally:
		server.close()

main()
