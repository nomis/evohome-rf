#!/usr/bin/env python3

import argparse
import fcntl
import os
import serial
import socket
import struct
import syslog
import systemd.daemon
import termios
import time
import yaml

IP6_GROUP = "ff02::114"
SRC_PORT = 17734
DST_PORT = 1986

def main_loop(device, interface, debug):
	with serial.Serial(device, 115200) as input:
		# Configure read() to block until a whole line is received
		attrs = termios.tcgetattr(input.fd)
		attrs[3] |= termios.ICANON
		attrs[6][termios.VMIN] = 1
		attrs[6][termios.VTIME] = 0
		termios.tcsetattr(input.fd, termios.TCSAFLUSH, attrs)
		fcntl.fcntl(input.fd, fcntl.F_SETFL, 1)

		with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as output:
			output.bind(("", SRC_PORT))
			output.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)

			# Transmit on a specific interface
			mcast_if = struct.pack("@i", socket.if_nametoindex(interface))
			output.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, mcast_if)

			systemd.daemon.notify("READY=1")

			while True:
				for line in list(filter(None, os.read(input.fd, 4096).replace(b"\r", b"").split(b"\n"))):
					if not line.startswith("#"):
						now = time.time()
						output.sendto(str(now).encode("ascii") + b"\n" + line, (IP6_GROUP, DST_PORT))
						syslog.syslog(line.decode("ascii", "replace"))


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Evohome RF Receiver")
	parser.add_argument("-d", "--debug", action="store_true", help="enable debug")
	parser.add_argument("-l", "--line", metavar="DEVICE", type=str, required=True, help="serial device to open")
	parser.add_argument("-i", "--interface", metavar="INTERFACE", type=str, required=True, help="network interface to use")
	args = parser.parse_args()

	syslog.openlog("evohome-rf")
	main_loop(args.line, args.interface, args.debug)
