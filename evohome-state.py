#!/usr/bin/env python3

import argparse
import datetime
import os
import re
import socket
import struct
import systemd.daemon
import time
import tzlocal
import yaml

from evohome_net import *


socket.MCAST_JOIN_SOURCE_GROUP = 46
re_message = re.compile(r"(?P<rssi>[0-9]{3}|---) +(?P<type>I|RQ|RP|W) +--- +(?P<dev0>[0-9]{2}:[0-9]{6}|--:------) +(?P<dev1>[0-9]{2}:[0-9]{6}|--:------) +(?P<dev2>[0-9]{2}:[0-9]{6}|--:------) +(?P<cmd>[0-9A-F]{4}) +(?P<length>[0-9]{3}) +(?P<data>(?:[0-9A-F]{2})+)")

state_file = "/dev/shm/evohome.state"

cls_controller = [1]
cls_sensor = [4, 34]
cls_actuator = [4]
cls_relay = [13]

local_tz = tzlocal.get_localzone()


class Device:
	def __init__(self, data):
		if data == "--:------":
			self.cls = None
			self.id = None
		else:
			(self.cls, self.id) = [int(x) for x in data.split(":")]

	def __str__(self):
		return "{0:02d}:{1:06d}".format(self.cls, self.id)

	@property
	def controller(self):
		return self.cls in cls_controller

	@property
	def sensor(self):
		return self.cls in cls_sensor

	@property
	def actuator(self):
		return self.cls in cls_actuator

	@property
	def relay(self):
		return self.cls in cls_relay


def parse_temp(data):
	temp_c = struct.unpack("!H", data)[0]
	if temp_c == 0x7FFF:
		return None
	return temp_c/100

def parse_seconds(data):
	s = struct.unpack("!H", data)[0]
	return s / 10

def parse_demand(data):
	pc = struct.unpack("!B", data)[0]
	return pc / 2

def parse_datetime(data):
	(mins, hour, day, month, year) = struct.unpack("!BBBBH", data)
	if year == 0xFFFF or month == 0xFF or day == 0xFF or hour == 0xFF or mins == 0xFF:
		return None
	is_dst = time.localtime().tm_isdst == 1
	return local_tz.localize(datetime.datetime(year, month, day, hour, mins), is_dst=is_dst)

def parse_battery(data):
	(level, low) = struct.unpack("!BB", data)
	if level == 0xFF:
		level = 100
	else:
		level = level / 2
	low = not bool(low)
	return { "level": level, "low": low }


class EvohomeState:
	def __init__(self):
		self.commands = {
			0x0008: self.process_relay_demand,
			0x1060: self.process_battery_info,
			0x12B0: self.process_zone_window,
			0x1F09: self.process_controller_interval,
			0x2309: self.process_set_point,
			0x2349: self.process_set_point_override,
			0x2E04: self.process_controller_mode,
			0x30C9: self.process_zone_temp,
			0x3150: self.process_zone_demand,
			0x3EF0: self.process_relay_state,
		}
		self.load_state()

	def process_controller_interval(self, now, type, dev0, dev1, dev2, data):
		if dev0 is None:
			return

		if dev0.controller:
			if len(data) != 3:
				return

			seconds = parse_seconds(data[1:])
			if seconds is not None:
				self.set_value(now, ["controller", dev0, "interval_s"], seconds)

	def process_controller_mode(self, now, type, dev0, dev1, dev2, data):
		if dev0 is None:
			return

		if dev0.controller:
			if len(data) != 8:
				return

			mode = { 0: "normal", 1: "off", 2: "economy", 3: "away", 4: "day off", 7: "custom" }.get(data[0], "unknown")
			until = parse_datetime(data[1:7])
			persist = { 0: "permanent", 1: "temporary" }.get(data[7], "unknown")
			self.set_value(now, ["controller", dev0, "mode", "state"], mode)
			self.set_value(now, ["controller", dev0, "mode", "until"], until)
			self.set_value(now, ["controller", dev0, "mode", "persist"], persist)

	def process_zone_temp(self, now, type, dev0, dev1, dev2, data):
		if dev0 is None:
			return

		if dev0.controller:
			if len(data) % 3 != 0:
				return

			while data:
				zone = int(data[0])
				temp = parse_temp(data[1:3])
				if temp is not None:
					self.set_value(now, ["controller", dev0, "zones", zone, "temp_c"], temp)

				data = data[3:]
		elif dev0.sensor:
			if len(data) != 3:
				return

			temp = parse_temp(data[1:3])
			if temp is not None:
				self.set_value(now, ["sensor", dev0, "temp_c"], temp)

	def process_set_point(self, now, type, dev0, dev1, dev2, data):
		if dev0 is None or dev2 is None:
			return

		if dev0.controller:
			if len(data) % 3 != 0:
				return

			while data:
				zone = data[0]
				temp = parse_temp(data[1:3])
				if temp is not None:
					self.set_value(now, ["controller", dev0, "zones", zone, "set_point_c"], temp)

				data = data[3:]
		elif dev0.sensor and dev2.controller:
			if len(data) != 3:
				return

			zone = data[0]
			temp = parse_temp(data[1:3])
			if temp is not None:
				self.set_value(now, ["controller", dev2, "zones", zone, "set_point_c"], temp)

	def process_set_point_override(self, now, type, dev0, dev1, dev2, data):
		if dev0 is None:
			return

		if dev0.controller:
			if len(data) not in [7, 13]:
				return

			zone = data[0]
			temp = parse_temp(data[1:3])
			mode = { 0: "auto", 2: "permanent", 4: "temporary" }.get(data[3], "unknown")
			self.set_value(now, ["controller", dev0, "zones", zone, "set_point_c"], temp)
			self.set_value(now, ["controller", dev0, "zones", zone, "set_point_override", "temp_c"], temp)
			self.set_value(now, ["controller", dev0, "zones", zone, "set_point_override", "mode"], mode)

			when = None
			if len(data) == 13:
				when = parse_datetime(data[7:13])
			self.set_value(now, ["controller", dev0, "zones", zone, "set_point_override", "until"], when)


	def process_any_demand(self, now, type, dev0, dev1, dev2, data):
		if dev0 is None or dev2 is None or not dev2.controller:
			return

		if dev0.controller:
			if len(data) != 2:
				return

			relay = { 0xFC: "boiler", 0xFA: "hot_water", 0xF9: "heating" }.get(data[0], "unknown")
			demand = parse_demand(data[1:2])
			self.set_value(now, ["controller", dev2, "demand", relay], demand)
		elif dev0.actuator:
			if len(data) != 2:
				return

			zone = data[0]
			demand = parse_demand(data[1:2])
			self.set_value(now, ["controller", dev2, "zones", zone, "demand"], demand)

	def process_relay_demand(self, now, type, dev0, dev1, dev2, data):
		self.process_any_demand(now, type, dev0, dev1, dev2, data)

	def process_zone_demand(self, now, type, dev0, dev1, dev2, data):
		self.process_any_demand(now, type, dev0, dev1, dev2, data)

	def process_zone_window(self, now, type, dev0, dev1, dev2, data):
		if dev0 is None or dev2 is None:
			return

		if dev0.sensor and dev2.controller:
			if len(data) != 3:
				return

			zone = data[0]
			window = data[1] != 0
			self.set_value(now, ["controller", dev2, "zones", zone, "open_window"], window)

	def process_relay_state(self, now, type, dev0, dev1, dev2, data):
		if dev0 is None:
			return

		if dev0.relay:
			if len(data) != 3:
				return

			demand = parse_demand(data[1:2])
			self.set_value(now, ["relay", dev0, "demand"], demand)

	def process_battery_info(self, now, type, dev0, dev1, dev2, data):
		if dev0 is None or dev2 is None:
			return

		if len(data) != 3:
			return

		battery = parse_battery(data[1:3])

		if dev2.controller:
			if dev2.sensor:
				zone = data[0]
				self.set_value(now, ["controller", dev2, "zones", zone, "battery", dev0], battery)

		if dev0.actuator:
			self.set_value(now, ["actuator", dev0, "battery"], battery)
		elif dev0.sensor:
			self.set_value(now, ["sensor", dev0, "battery"], battery)
		elif dev0.relay:
			self.set_value(now, ["relay", dev0, "battery"], battery)

	def process_message(self, now, rssi, type, dev0, dev1, dev2, cmd, length, data):
		rssi = None if rssi == "---" else int(rssi)
		dev0 = Device(dev0)
		dev1 = Device(dev1)
		dev2 = Device(dev2)
		cmd = int(cmd, 16)
		length = int(length)

		if len(data) != length * 2:
			return

		if cmd not in self.commands:
			return

		if type not in ["I", "RP"]:
			return

		self.commands[cmd](now, type, dev0, dev1, dev2, bytes.fromhex(data))
		self.save_state()

	def load_state(self):
		try:
			with open(state_file, "r") as f:
				self.state = yaml.safe_load(f)
		except FileNotFoundError:
			self.state = {}
		self.dirty = False

	def set_value(self, now, keys, value):
		p = self.state
		keys = [str(x) if type(x) == Device else x for x in keys]

		while len(keys) > 1:
			if keys[0] not in p:
				p[keys[0]] = {}
			p = p[keys[0]]
			keys = keys[1:]

		p[keys[0]] = value
		p[keys[0] + ".ts"] = now
		self.dirty = True

	def save_state(self):
		if not self.dirty:
			return
		with open(state_file + "~", "w") as f:
			yaml.dump(self.state, f, default_flow_style=False)
		os.rename(state_file + "~", state_file)


def main_loop(interface, source):
	with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as input:
		ifidx = socket.if_nametoindex(interface)
		input.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		input.bind((IP6_GROUP, DST_PORT, 0, ifidx))

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

		input.setsockopt(socket.IPPROTO_IPV6, socket.MCAST_JOIN_SOURCE_GROUP, gsreq)

		source = (socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, source)), SRC_PORT, 0, ifidx)
		state = EvohomeState()

		systemd.daemon.notify("READY=1")

		while True:
			(packet, address) = input.recvfrom(65536)
			address = (address[0].split("%")[0],) + address[1:]
			if address == source:
				(now, packet) = packet.decode("ascii", "replace").split("\n")
				now = datetime.datetime.fromtimestamp(float(now), datetime.timezone.utc)
				match = re_message.fullmatch(packet)
				print(packet)
				if match:
					state.process_message(now, **match.groupdict())


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Evohome State Monitor")
	parser.add_argument("-i", "--interface", metavar="INTERFACE", type=str, required=True, help="network interface to use")
	parser.add_argument("-s", "--source", metavar="IP", type=str, required=True, help="source IP address")
	args = parser.parse_args()

	main_loop(args.interface, args.source)
