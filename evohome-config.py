#!/usr/bin/env python3

import argparse
import codecs
import datetime
import os
import re
import select
import socket
import struct
import sys
import time
import yaml
import zlib

from evohome_net import *


socket.MCAST_JOIN_SOURCE_GROUP = 46


class Device:
	def __init__(self, data):
		if data == "--:------":
			self.cls = None
			self.id = None
		else:
			(self.cls, self.id) = [int(x) for x in data.split(":")]

	def __str__(self):
		return "{0:02d}:{1:06d}".format(self.cls, self.id)

	def __eq__(self, other):
		return self.cls == other.cls and self.id == other.id


class EvohomeConfig:
	def __init__(self, interface, source, controller, filename):
		self.open_socket(interface, source)
		self.gateway = Device("18:{0:6d}".format(os.getpid() % 0x3FFFF))
		self.controller = Device(controller)
		self.commands = {
			0x0004: self.process_zone_name,
			0x0404: self.process_zone_schedule,
		}
		self.filename = filename
		self.load_config()

	def open_socket(self, interface, source):
		self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
		ifidx = socket.if_nametoindex(interface)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.bind((IP6_GROUP, DST_PORT, 0, ifidx))

		src_sa = (struct.pack("@H", socket.AF_INET6)
			+ struct.pack("!HI", SRC_PORT, 0)
			+ socket.inet_pton(socket.AF_INET6, source)
			+ struct.pack("@I", ifidx)
			+ b"\x00" * 100)
		dst_sa = (struct.pack("@H", socket.AF_INET6)
			+ struct.pack("!HI", DST_PORT, 0)
			+ socket.inet_pton(socket.AF_INET6, IP6_GROUP)
			+ struct.pack("@I", ifidx)
			+ b"\x00" * 100)
		padding = b"\x00" * (len(struct.pack("@P", 0)) - len(struct.pack("@I", 0)))
		gsreq = struct.pack("@I", socket.if_nametoindex(interface)) + padding + dst_sa + src_sa

		self.sock.setsockopt(socket.IPPROTO_IPV6, socket.MCAST_JOIN_SOURCE_GROUP, gsreq)

		self.addr = (socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, source)), SRC_PORT, 0, ifidx)

	def make_request(self, type, cmd, data, timeout=10, attempts=3):
		tx_packet = "{5} - {0} {1} - {2:04x} {3:03d} {4}\r\n".format(
			self.gateway, self.controller, cmd,
			len(data), codecs.encode(data, "hex").decode("ascii").upper(), type)

		result = None
		done = False
		sent = True
		while attempts and sent and not done:
			attempts -= 1
			remaining = timeout
			timeout *= 2

			self.sock.sendto(tx_packet.encode("ascii"), self.addr)
			print(tx_packet.strip())
			sent = False

			while remaining > 0 and not done:
				start = time.time()
				(rfds, wfds, xfds) = select.select([self.sock], [], [], remaining)
				remaining -= max(0, time.time() - start)
				if self.sock in rfds:
					(rx_packet, address) = self.sock.recvfrom(65536)
					address = (address[0].split("%")[0],) + address[1:]
					if address == self.addr:
						(now, rx_packet) = rx_packet.decode("ascii", "replace").split("\n")
						now = datetime.datetime.fromtimestamp(float(now), datetime.timezone.utc)
						match = re_message.fullmatch(rx_packet)
						print(rx_packet)
						if match:
							match = match.groupdict()
							self.parse_message(match)
							if (match["type"] == type and match["dev0"] == self.gateway
									and match["dev1"] == self.controller
									and match["cmd"] == cmd):
								sent = True
							if (match["type"] == {"RQ": "RP", "W": "I"}.get(type) and match["dev0"] == self.controller
									and match["dev1"] == self.gateway
									and match["cmd"] == cmd):
								result = self.process_message(**match)
								done = True
								time.sleep(2)

		return (done, result)

	def get_zones(self, zones=None):
		if zones is None:
			zones = range(0, 256)

		good_zones = []
		for zone in zones:
			(ok, result) = self.make_request("RQ", 0x0004, struct.pack("@BB", zone, 0))
			if not ok:
				return
			if not result:
				break
			good_zones.append(zone)

		for zone in good_zones:
			total = 0

			self.schedule_block = 1
			self.schedule_data = b""

			(ok, result) = self.make_request("RQ", 0x0404, struct.pack("@BBBBBBB", zone, 32, 0, 8, 0, 1, total))
			if not ok:
				return
			if not result:
				return

			total = self.schedule_total

			for block in range(2, total + 1):
				(ok, result) = self.make_request("RQ", 0x0404, struct.pack("@BBBBBBB", zone, 32, 0, 8, 0, block, total))
				if not ok:
					return
				if not result:
					return

			self.set_value(["zone", zone, "schedule"], list(self.decode_schedule(self.schedule_data)))
			self.save_config()

	def set_zones(self, zones=None):
		if zones is None:
			zones = range(0, 256)

		good_zones = []
		for zone in zones:
			name = self.config.get("zone", {}).get(zone, {}).get("name")
			if name is None:
				continue
			name = name.encode("ascii", "replace")[0:20]
			name += b"\x00" * (20 - len(name))
			(ok, result) = self.make_request("W", 0x0004, struct.pack("@BB", zone, 0) + name)
			if not ok:
				return
			if not result:
				break
			good_zones.append(zone)

		for zone in good_zones:
			schedule = self.config.get("zone", {}).get(zone, {}).get("schedule")
			if schedule is None:
				continue
			schedule_data = self.encode_schedule(zone, schedule)
			block_size = 41
			total = len(schedule_data) // block_size
			if len(schedule_data) % block_size != 0:
				total += 1
			self.schedule_total = total

			for block in range(1, total + 1):
				data = schedule_data[(block - 1) * block_size:block * block_size]
				self.schedule_block = block
				self.schedule_data = data
				padding = b"" # b"\x00" * (block_size - len(data))

				(ok, result) = self.make_request("W", 0x0404, struct.pack("@BBBBBBB", zone, 32, 0, 8, len(data), block, total) + data + padding)
				if not ok:
					return
				if not result:
					return

	def decode_schedule(self, data):
		data = zlib.decompress(data)

		for record in [data[i:i+20] for i in range(0, len(data), 20)]:
			(zone, day, time, temp) = struct.unpack("<xxxxLLLHxx", record)
			day = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][day]
			hours = time // 60
			minutes = time % 60
			temp /= 100

			yield { "day": day, "time": "{0:02d}:{1:02d}".format(hours, minutes), "temp": temp }

	def encode_schedule(self, zone, records):
		data = b""

		for record in records:
			day = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].index(record["day"])
			time = [int(x) for x in record["time"].split(":")]
			time = time[0] * 60 + time[1]
			temp = int(record["temp"] * 100)

			data += struct.pack("<xxxxLLLHxx", zone, day, time, temp)

		cobj = zlib.compressobj(level=9, wbits=14)
		data = cobj.compress(data)
		data += cobj.flush()
		return data

	def process_zone_name(self, type, dev0, dev1, dev2, data):
		if len(data) != 22:
			return False

		if data[2:] == b"\x7F" * 20:
			return False

		zone = data[0]
		name = data[2:].decode("ascii", "replace").rstrip("\0")
		self.set_value(["zone", zone, "name"], name)

		return True

	def process_zone_schedule(self, type, dev0, dev1, dev2, data):
		if len(data) < 7:
			return False

		zone = data[0]
		size = data[4]
		block = data[5]
		blocks = data[6]

		if type == "RP":
			if size != len(data[7:]):
				return False

			if not block or not blocks:
				return False

			self.schedule_total = blocks
			if self.schedule_block == block:
				self.schedule_data += data[7:]
				self.schedule_block += 1
				return True
		elif type == "I":
			if len(data) != 7:
				return False

			if block != self.schedule_block:
				return False

			if size != len(self.schedule_data):
				return False

			if block < self.schedule_total:
				if blocks == self.schedule_total:
					return True
			elif block == self.schedule_total:
				if blocks == 0: # 0xFF == failure
					return True

		return False

	def parse_message(self, data):
		data["rssi"] = None if data["rssi"] == "---" else int(data["rssi"])
		data["dev0"] = Device(data["dev0"])
		data["dev1"] = Device(data["dev1"])
		data["dev2"] = Device(data["dev2"])
		data["cmd"] = int(data["cmd"], 16)
		data["length"] = int(data["length"])
		data["data"] = bytes.fromhex(data["data"])

	def process_message(self, rssi, type, dev0, dev1, dev2, cmd, length, data):
		if len(data) != length:
			return False

		if cmd not in self.commands:
			return False

		if type not in ["RP", "I"]:
			return False

		if dev0 != self.controller:
			return False

		if dev1 != self.gateway:
			return False

		ok = self.commands[cmd](type, dev0, dev1, dev2, data)
		self.save_config()
		return ok

	def load_config(self):
		try:
			with open(self.filename, "r") as f:
				self.config = yaml.safe_load(f)
		except FileNotFoundError:
			self.config = {}
		self.dirty = False

	def set_value(self, keys, value):
		p = self.config
		keys = [str(x) if type(x) == Device else x for x in keys]

		while len(keys) > 1:
			if keys[0] not in p:
				p[keys[0]] = {}
			p = p[keys[0]]
			keys = keys[1:]

		p[keys[0]] = value
		self.dirty = True

	def save_config(self):
		if not self.dirty:
			return
		with open(self.filename, "w") as f:
			yaml.dump(self.config, f, default_flow_style=False)


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Evohome Config")
	parser.add_argument("-i", "--interface", metavar="INTERFACE", type=str, required=True, help="network interface to use")
	parser.add_argument("-s", "--source", metavar="IP", type=str, required=True, help="remote IP address")
	parser.add_argument("-c", "--controller", metavar="DEVICE", type=str, required=True, help="controller device")
	parser.add_argument("-f", "--filename", metavar="FILENAME", type=str, required=True, help="output file")
	parser.add_argument("-z", "--zone", metavar="ZONE", type=int, action="append", help="output file")
	subparsers = parser.add_subparsers(dest="action")
	get = subparsers.add_parser("get", help="Get config")
	set = subparsers.add_parser("set", help="Set config")
	args = parser.parse_args()

	config = EvohomeConfig(args.interface, args.source, args.controller, args.filename)
	if args.action == "get":
		config.get_zones(args.zone)
	elif args.action == "set":
		config.set_zones(args.zone)
	else:
		print("No action specified")
		sys.exit(2)
