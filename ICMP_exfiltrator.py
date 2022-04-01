#!/usr/bin/python3

import signal
from pwn import *
from scapy.all import *

#Colors
class colors():
	GREEN = "\033[0;32m\033[1m"
	RED = "\033[0;31m\033[1m"
	BLUE = "\033[0;34m\033[1m"
	YELLOW = "\033[0;33m\033[1m"
	PURPLE = "\033[0;35m\033[1m"
	TURQUOISE = "\033[0;36m\033[1m"
	GRAY = "\033[0;37m\033[1m"
	END = "\033[0m"

def def_handler(sig, frame):
	print(colors.RED + "\n[!] Exiting..." + colors.END)
	sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

if len(sys.argv) < 2:
	print(colors.YELLOW + "\n[ł] Usage: " + sys.argv[0] + colors.GREEN + " <IFACE>" + colors.END)
	sys.exit(1)

interface = sys.argv[1]

def data_parser(packet):
	if packet.haslayer(ICMP):
		if packet[ICMP].type == 8:
			data = packet[ICMP].load[-4:].decode("utf-8")
			print(data, flush=True, end='')

if __name__ == '__main__':

	try:
		print("")
		p = log.progress(colors.GREEN + "Sniffing" + colors.END)
		sniff(iface=interface, prn=data_parser)

	except Exception as e:
		log.failure(str(e))
		sys.exit(1)
