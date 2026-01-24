#!/usr/bin/python3
import socket
import datetime
import logging
import csv
import html #osetreni vypisu dat
from concurrent.futures import ThreadPoolExecutor

HOST = '0.0.0.0'
PORT = 8080
LOG_FILE = 'honeypot_http_logs.csv'
SERVER_BANNER = 'Apache/2.4.41 (Ubuntu)'
PHP_VERSION = 'PHP/7.4.3'


#Nastaveni zakladni konfigurace logovani
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

def logCsv(timestamp, ip, port, method, path, status, userAgent):
	row = [timestamp, ip, port, method, path, status, userAgent]
	try:
		with open(LOG_FILE, 'a') as file:
			write = csv.writer(file)
			write.writerow(row)
	except Exception as e:
		logging.warning('Failed to write to log file', e)

def handleClient(client, addr):
	try:
		while True:
			data = client.recv(1024).decode()
			if not data:
				break

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

			httpResponse = (
				"HTTP/1.1 404 Not Found\r\n"
				f"Server: {SERVER_BANNER}\r\n"
				f"X-Powered-By: {PHP_VERSION}\r\n"
				"Content-Type: text/html\r\n"
				"Connection: close \r\n"
				f"Content-Length: {len(bodyResponse)}\r\n\r\n" + bodyResponse
			)
			client.send(httpResponse.encode())
			logCsv(datetime.datetime.now(), addr[0], addr[1], method, path, status, userAgent)
	except Exception as e:
		print(e)
	finally:
		client.close()

def main():
	print('Honeypot started...')
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	server.bind((HOST, PORT))
	server.listen(5)

	try:
		print(f'Honeypot is listening on {HOST}:{PORT}')

		with ThreadPoolExecutor(max_workers=10) as executor:
			while True:
				client, addr = server.accept()
				print(f'Session accepted by {addr[0]}:{addr[1]}\n')
				executor.submit(handleClient, client, addr)
	except KeyboardInterrupt:
		print('Honeypot was stopped by user')
	finally:
		server.close()

main()
