#!/usr/bin/python3
# this script process the apache log on updates.vpex.org to check some stats

import argparse
import logging
import datetime
import pprint
import socket

XK_Hosts = {}
XN_Hosts = {}

def process_line(line):
	global XK_Hosts
	global XN_Hosts

	#if not a log line we're interested in
	if line.index('fw/info.json?version=') < 0:
		return

	cols = line.split(' ')
	#print("line:%s" % cols);
	data = { 'ip' : cols[0],
				 'date_str' : cols[3][1:],
				 'method' : cols[5][1:],
				 'uri' : cols[6],
				 'response_code' : cols[7]
				 }

	data['date'] = datetime.datetime.strptime(data['date_str'], "%d/%b/%Y:%H:%M:%S")
	data['version'] = data['uri'].split("version=",1)[1]

	#pprint.pprint(data)
	if data['uri'].startswith('/en/fw/'):
		XN_Hosts[data['ip']] = data
	elif data['uri'].startswith('/ek/fw/'):
		XK_Hosts[data['ip']] = data
	else:
		print("unhandled URI: %s " %line)


def process_log(file_path):
	with open(file_path) as fin:
		for line in fin:
			try:
				process_line(line)
			except:
				pass
				#print("not processing: %s" % line)

def print_report(Hosts):
	ips = sorted(Hosts)
	#pprint.pprint(Hosts)
	for ip in ips:
		h = Hosts[ip]
		#pprint.pprint(h)
		hostname = ''
		try:
			hostname = socket.gethostbyaddr(h['ip'])[0]
		except:
			hostname = h['ip']
		print("%-16s %20s %50s %30s" % (h['ip'], h['version'], hostname,  h['date_str']))
		#print("{0:<20s}  {1:<20s} {2:<20s} {3:<20s}".format(h['ip'], h['version'], hostname,  h['date_str']))

def main():
	""" main script. """
	parser = argparse.ArgumentParser(description='Process logs.')
	parser.add_argument("-f", "--in-file", help="apache log file")

	args = parser.parse_args()


	if args.in_file:
		process_log(args.in_file)

	print("XOkey connections =====  %d" % (len(XK_Hosts)));
	print_report(XK_Hosts)
	print("\n\n")
	print("XOnet connections =====  %d"  % (len(XN_Hosts)));
	print_report(XN_Hosts)

if __name__ == '__main__':
  main()