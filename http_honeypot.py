#!/usr/bin/python3
import socket
from datetime import datetime, UTC
import logging
import csv

HOST = '0.0.0.0'
PORT = 8080
LOG_FILE = 'honeypot_http_logs.csv'


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


def main():
	print('Honeypot started...')
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	try:
		server.bind((HOST, PORT))
		server.listen(5)

		print(f'Honeypot is listening on {HOST}:{PORT}')

		while True:
			client, addr = server.accept()
			print(f'Session accepted by {addr[0]}:{addr[1]}\n')

			data = client.recv(1024).decode()

			#Rozdeli data, ziskam GET / HTTP1.1 jako jeden celek
			parsedData = data.split('\r\n')
			#Rozdelim data na jednotlive kusy GET, /, HTTP1.1
			parts = parsedData[0].split()

			#Zjistim jestli list ma prvky
			method = parts[0] if len(parts) > 0 else 'UNKNOWN'
			path = parts[1] if len(parts) > 1 else '/'

			#print(path)
			#print(parsedData)
			#Hledani user-agenta v prijmutych a dekodovanych datech
			userAgent = 'UNKNOWN'
			for item in parsedData:
				if item.lower().startswith('user-agent'):
					#.split() rozdeli podle : ale jenom jednou (:, 1)
					#.strip() ocisti data na zacatku a na konci od neviditelnych znaku
					userAgent = item.split(':', 1)[1].strip()

			if path == '/admin':
				bodyResponse = "<html><body><h1>Admin page hello</h1></body></html>"
				bodyLenght = str(len(bodyResponse))
				httpResponseAdmin = (
					"HTTP/1.1 200 OK\r\n"
					"Content-Type: text/html\r\n"
					"Connection: close \r\n"
					"Content-Length:"+ bodyLenght +" \r\n\r\n"
					+ bodyResponse
				)
				client.send(httpResponseAdmin.encode())
				status = 200
			else:
				bodyResponse = "<html><body><h1>404 Not Found</h1></body></html>"
				bodyLenght = str(len(bodyResponse))
				httpResponse = (
					"HTTP/1.1 404 Not Found\r\n"
					"Content-Type: text/html\r\n"
					"Connection: close \r\n"
					"Content-Length:"+ bodyLenght +"\r\n\r\n"
					+ bodyResponse
				)
				client.send(httpResponse.encode())
				status = 404
			logCsv(datetime.now(UTC), addr[0], addr[1], method, path, status, userAgent)

	except KeyboardInterrupt:
		print('Honeypot was stopped by user')
	finally:
		server.close()

main()
