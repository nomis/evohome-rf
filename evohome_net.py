import re

IP6_GROUP = "ff02::114"
SRC_PORT = 17734
DST_PORT = 1986

re_message = re.compile(r"(?P<rssi>[0-9]{3}|---) +(?P<type>I|RQ|RP|W) +--- +(?P<dev0>[0-9]{2}:[0-9]{6}|--:------) +(?P<dev1>[0-9]{2}:[0-9]{6}|--:------) +(?P<dev2>[0-9]{2}:[0-9]{6}|--:------) +(?P<cmd>[0-9A-F]{4}) +(?P<length>[0-9]{3}) +(?P<data>(?:[0-9A-F]{2})+)")

cls_controller = [1]
cls_sensor = [4, 34]
cls_actuator = [4]
cls_opentherm = [10]
cls_relay = [13]
