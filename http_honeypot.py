#!/usr/bin/python3
import socket
import datetime
import logging

HOST = '0.0.0.0'
PORT = 8080
LOG_FILE = 'honeypot_logs.csv'

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
			#print(data)

			parsedData = data.split()
			print(parsedData)
			print('\n')
			path = None
			for line in parsedData:
				#print(line)
				if line == '/admin':
					path = line
					#print(path)
			if path == '/admin':
				httpResponseAdmin = (
					"HTTP/1.1 200 OK\r\n"
					"Content-Type: text/html\r\n"
					"Connection: close \r\n"
					"Content-Length: 45\r\n\r\n"
					"<html><body><h1>Admin page</h1></body></html>"
				)
				client.send(httpResponseAdmin.encode())
			else:
				httpResponse = (
					"HTTP/1.1 404 Not Found\r\n"
					"Content-Type: text/html\r\n"
					"Connection: close \r\n"
					"Content-Length: 48\r\n\r\n"
					"<html><body><h1>404 Not Found</h1></body></html>"
				)
				client.send(httpResponse.encode())

	except KeyboardInterrupt:
		print('Honeypot was stopped by user')
	finally:
		server.close()

main()
