#!/usr/bin/env python3

import argparse
import array
import fcntl
import os
import select
import serial
import socket
import struct
import syslog
import systemd.daemon
import termios
import time
import yaml

from evohome_net import *

def main_loop(device, interface, debug):
	with serial.Serial(device, 115200) as input:
		# Configure baud rate
		TCGETS2 = 0x802C542A
		TCSETS2 = 0x402C542B
		BOTHER = 0o010000

		buf = array.array('i', [0] * 64)
		fcntl.ioctl(input.fd, TCGETS2, buf)
		buf[2] &= ~termios.CBAUD
		buf[2] |= BOTHER
		buf[9] = buf[10] = 250000
		try:
			fcntl.ioctl(input.fd, TCSETS2, buf)
		except IOError:
			raise ValueError("Failed to set baud rate")

		# Configure read() to block until a whole line is received
		attrs = termios.tcgetattr(input.fd)
		attrs[3] |= termios.ICANON
		attrs[6][termios.VMIN] = 1
		attrs[6][termios.VTIME] = 0
		termios.tcsetattr(input.fd, termios.TCSAFLUSH, attrs)
		fcntl.fcntl(input.fd, fcntl.F_SETFL, 1)

		with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as output:
			output.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			output.bind(("", SRC_PORT))
			output.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)

			# Transmit on a specific interface
			ifidx = socket.if_nametoindex(interface)
			mcast_if = struct.pack("@i", ifidx)
			output.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, mcast_if)

			systemd.daemon.notify("READY=1")
			buffer = b""

			while True:
				(rlist, wlist, xlist) = select.select([input.fd, output], [], [])

				if input.fd in rlist:
					buffer += os.read(input.fd, 65536)
					lines = buffer.split(b"\r\n")
					if not buffer.endswith(b"\r\n"):
						buffer = lines[-1]
						lines = lines[:-1]
					else:
						buffer = b""

					now = time.time()
					for line in filter(None, lines):
						if debug:
							syslog.syslog(line.decode("ascii", "replace"))
						if not line.startswith(b"#"):
							output.sendto(str(now).encode("ascii") + b"\n" + line, (IP6_GROUP, DST_PORT))

				if output in rlist:
					(packet, address) = output.recvfrom(65536)
					if address[3] == ifidx:
						os.write(input.fd, packet)


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Evohome RF Receiver")
	parser.add_argument("-d", "--debug", action="store_true", help="enable debug")
	parser.add_argument("-l", "--line", metavar="DEVICE", type=str, required=True, help="serial device to open")
	parser.add_argument("-i", "--interface", metavar="INTERFACE", type=str, required=True, help="network interface to use")
	args = parser.parse_args()

	syslog.openlog("evohome-rf")
	main_loop(args.line, args.interface, args.debug)
