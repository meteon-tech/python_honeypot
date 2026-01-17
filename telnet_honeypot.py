#!/usr/bin/python3
import socket
import logging
import csv
import datetime
from concurrent.futures import ThreadPoolExecutor

HOST = '0.0.0.0'
PORT = 2323
LOG_FILE = 'telnet_honeypot_logs.csv' 


def logCsv(timestamp, ip, port, command):
	row = [timestamp, ip, port, command]
	try:
		with open(LOG_FILE, 'a') as file:
			write = csv.writer(file)
			write.writerow(row)
	except Exception as e:
		print(f'Failed to write to log file: {e}')


def handleClient(client, addr):
	print(addr[0], addr[1])
	try:
		client.settimeout(30)
		while True:
			client.send(b'root~')
			data = client.recv(1024)
			if not data:
				break
			print(data)
			command = data.decode().strip()
			logCsv(datetime.datetime.now(), addr[0], addr[1], command)
			if command.lower() == 'exit':
				break
			elif command.lower() == 'whoami':
				client.send(b'root\r\n')
	except Exception as e:
		print(e)
	finally:
		client.close()


def main():
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	server.bind((HOST, PORT))
	server.listen(10)

	try:
		with ThreadPoolExecutor(max_workers=10) as executor:
			while True:
				client, addr = server.accept()
				executor.submit(handleClient, client, addr)
			#thread = threading.Thread(target=handleClient, args=(client, addr))
			#thread.daemon = True
			#thread.start()
	except KeyboardInterrupt:
		print('Telnet was stopped by user')
	finally:
		server.close()

main()
