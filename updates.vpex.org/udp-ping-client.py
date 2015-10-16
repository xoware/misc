#!/usr/bin/python3
# this script process the apache log on updates.vpex.org to check some stats

import argparse
import logging
import datetime
import pprint
import socket


def main():
	""" main script. """
	port = 45000
	host = '0.0.0.0'

	parser = argparse.ArgumentParser(description='Process logs.')
	parser.add_argument("-p", "--port", help="port number", type=int)
	parser.add_argument("-b", "--host", help="Bind to IP address")

	args = parser.parse_args()


	if args.port:
		port = args.port

	if args.host:
		host = args.host


	# SOCK_DGRAM is the socket type to use for UDP sockets
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	sock.sendto(bytes("hello\n", "utf-8"), (host, port))
	received = str(sock.recv(1024), "utf-8")

	print("Received: {}".format(received))


if __name__ == '__main__':
  main()