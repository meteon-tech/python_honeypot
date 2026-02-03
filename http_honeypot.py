#!/usr/bin/python3
import socket
import logging
import html #osetreni vypisu dat
import threading

HOST = '0.0.0.0'
PORT = 8080
LOG_FILE = 'honeypot_http_logs.csv'
SERVER_BANNER = 'Apache/2.4.41 (Ubuntu)'
PHP_VERSION = 'PHP/7.4.3'
MAX_CONNECTIONS = 10
MAX_REQUEST_SIZE = 4096

threadLimiter = threading.Semaphore(MAX_CONNECTIONS)


def handleClient(client, addr):
	ip = addr[0]
	port = addr[1]
	requestBuffer = b''
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

		data = requestBuffer.decode()

		#Rozdeli data, ziskam GET / HTTP1.1 jako jeden celek
		parsedData = data.split('\r\n')
		#Rozdelim data na jednotlive kusy GET, /, HTTP1.1
		parts = parsedData[0].split()

		#Zjistim jestli list ma prvky
		method = parts[0] if len(parts) > 0 else 'UNKNOWN'
		path = parts[1] if len(parts) > 1 else '/'

		#Hledani user-agenta v prijmutych a dekodovanych datech
		userAgent = 'UNKNOWN'
		for item in parsedData:
			if item.lower().startswith('user-agent'):
				#.split() rozdeli podle : ale jenom jednou (:, 1)
				#.strip() ocisti data na zacatku a na konci od neviditelnych znaku
				userAgent = item.split(':', 1)[1].strip()

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
		logging.info(f"{ip},{port},{method},{path},{status},{userAgent}")
	except socket.timeout:
		pass
	except Exception as e:
		print(e)
	finally:
		client.close()
		threadLimiter.release()

def main():
	logFormat = logging.Formatter('%(asctime)s,%(message)s', datefmt='%Y-%m-%d %H:%M:%S')

	fileHandler = logging.FileHandler(LOG_FILE, mode='a', encoding='utf-8')
	fileHandler.setFormatter(logFormat)

	logger = logging.getLogger()
	logger.setLevel(logging.INFO)
	logger.addHandler(fileHandler)

	print('Honeypot started...')
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	server.bind((HOST, PORT))
	server.listen(5)

	server.settimeout(1)

	try:
		print(f'Honeypot is listening on {HOST}:{PORT}')

		while True:
			try:
				client, addr = server.accept()
				if threadLimiter.acquire(blocking=False):
					thread = threading.Thread(target=handleClient, args=(client, addr))
					thread.daemon = True
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
