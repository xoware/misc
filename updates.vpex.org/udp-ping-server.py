#!/usr/bin/python3
# this script process the apache log on updates.vpex.org to check some stats

import argparse
import logging
import datetime
import pprint
import socket
import socketserver
import json

class MyUDPHandler(socketserver.BaseRequestHandler):
	"""
	This class works similar to the TCP handler class, except that
	self.request consists of a pair of data and client socket, and since
	there is no connection the client address must be given explicitly
	when sending data back via sendto().
	"""

	def handle(self):
			#data = self.request[0].strip()
			socket = self.request[1]
			#print("{} wrote:".format(self.client_address[0]))
			#print(data)
			response = { 'ip' : self.client_address[0] }
			print(response)
			socket.sendto(bytes(json.dumps(response).encode('utf-8')), self.client_address)


def main():
	""" main script. """
	port = 45000
	host = '0.0.0.0'

	parser = argparse.ArgumentParser(description='Process logs.')
	parser.add_argument("-p", "--port", help="port number", type=int)
	parser.add_argument("-b", "--bind", help="Bind to IP address")

	args = parser.parse_args()


	if args.port:
		port = args.port

	server = socketserver.UDPServer((host, port), MyUDPHandler)
	server.serve_forever()


if __name__ == '__main__':
  main()