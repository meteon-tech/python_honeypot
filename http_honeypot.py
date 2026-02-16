#!/usr/bin/python3
import socket
import logging
import html #osetreni vypisu dat
import threading
import configparser
import ipaddress
import sys


LOG_FILE = 'honeypot_http_logs.csv'

config = configparser.ConfigParser()
config.read('config.ini')

#osetreni vstupu z konfigurace
try:
	HOST = config.get('HTTP', 'Host', fallback='0.0.0.0')
	HTTP_PORT = config.getint('HTTP', 'Port', fallback=8080)
	MAX_CONNECTIONS = config.getint('HTTP', 'Connections', fallback=10)

	if not ipaddress.ip_address(HOST):
		print('Wrong ip address')


	if HTTP_PORT > 65535 or HTTP_PORT < 1:
		raise ValueError('Port is out of range')

	if MAX_CONNECTIONS <= 0:
		raise ValueError('Max connections must be greater than zero')

except Exception as e:
	print(f'Wrong configuration format: {e}')
	sys.exit()


logFormat = logging.Formatter('%(asctime)s,%(message)s', datefmt='%Y-%m-%d %H:%M:%S')

honeypotFile = logging.FileHandler(LOG_FILE)
honeypotFile.setFormatter(logFormat)

honeypotLog = logging.getLogger('honeypotHTTP')
honeypotLog.setLevel(logging.INFO)
honeypotLog.addHandler(honeypotFile)

#print(type(PORT))
SERVER_BANNER = 'Apache/2.4.41 (Ubuntu)'
PHP_VERSION = 'PHP/7.4.3'
MAX_REQUEST_SIZE = 4096

threadLimiter = threading.Semaphore(MAX_CONNECTIONS)

#funkce ktera bude obsluhovat prichozi spojeni v novem vlakne
def handleClient(client, addr):
	ip = addr[0]
	port = addr[1]
	requestBuffer = b''

	method = 'UNKNOWN'
	path = 'UNKNOWN'
	userAgent = 'UNKNOWN'
	status = 500

	try:
		client.settimeout(30)
		while True:
			chunk = client.recv(1024)
			if not chunk:
				break
			requestBuffer += chunk
			if len(requestBuffer) > MAX_REQUEST_SIZE:
				return

			if b'\r\n\r\n' in requestBuffer:
				break

		if not requestBuffer:
			return

		data = requestBuffer.decode(errors='replace')
		#print(data)


		#Rozdeli data, ziskam GET / HTTP1.1 jako jeden celek
		parsedData = data.splitlines()
		#Rozdelim data na jednotlive kusy GET, /, HTTP1.1
		if parsedData:
			parts = parsedData[0].split()
			if len(parts) >= 1:
				method = parts[0]

			if len(parts) >= 2:
				path = parts[1]
			else:
				path = '/'

		#Hledani user-agenta v prijmutych a dekodovanych datech
		for item in parsedData:
			if item.lower().startswith('user-agent:'):
				#.split() rozdeli podle : ale jenom jednou (:, 1)
				#.strip() ocisti data na zacatku a na konci od neviditelnych znaku
				try:
					userAgent = item.split(':', 1)[1].strip()
				except Exception as e:
					print(e)
		if path == '/admin':
			bodyResponse = f"""<!DOCTYPE html>
<html>
<head><title>Admin page</title></head>
<body>
	<h1>System</h1>
	<p>Server is running on PHP version: {PHP_VERSION}</p>
</body>
</html>"""
			status = 200
			statusText = '200 OK'
		else:
			bodyResponse = f"""<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
	<h1>Not Found</h1>
	<p>The requested URL {html.escape(path)} was not found on this server.
	<p>{SERVER_BANNER}</p>
</body>
</html>"""
			status = 404
			statusText = '404 Not Found'

		httpResponse = (
			f"HTTP/1.1 {statusText}\r\n"
			f"Server: {SERVER_BANNER}\r\n"
			f"X-Powered-By: {PHP_VERSION}\r\n"
			"Content-Type: text/html\r\n"
			"Connection: close \r\n"
			f"Content-Length: {len(bodyResponse.encode())}\r\n\r\n" + bodyResponse
		)
		client.send(httpResponse.encode())

		safeUserAgent = userAgent.replace(',', ';')
		safeMethod = method.replace(',', '')
		safePath = path.replace(',', '%2C')

		honeypotLog.info(f"{ip},{port},{safeMethod},{safePath},{status},{safeUserAgent}")
	except socket.timeout:
		print('socket timed out')

	except ConnectionError:
		honeypotLog.warning(f"Connection lost with {ip}")
	except Exception as e:
		honeypotLog.error(f"Error handling the client {e}")
	finally:
		client.close()
		threadLimiter.release()

def main():
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	server.bind((HOST, HTTP_PORT))

	server.listen(5)
	server.settimeout(1)

	try:
		print('HTTP started...')
		print(f'HTTP honeypot is listening on {HOST}:{HTTP_PORT}')

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

			print(f'Session accepted by {addr[0]}:{addr[1]}\n')
	except KeyboardInterrupt:
		print('Honeypot was stopped by user')
	finally:
		server.close()

main()
