
from ryu.base import app_manager
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv6
from ryu.lib.packet import ether_types

import sys
#import ruamel.yaml
import yaml
from datetime import datetime


def clean_switch(switch_devices):
	res = {}
	for device_name, device_info in switch_devices.items():
		if (device_info['status'] == 1):
			res[device_name] = device_info['mac']
	return res

class SimpleSwitchLogger(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(SimpleSwitchLogger, self).__init__(*args, **kwargs)

		self.switches = {}
		"""
		switches:
			- s1:
				- 1: h1_mac1
				- 2: h2_mac1
				...
			- s2:
				...
			...
		"""

		self.hosts = {}
		"""
		hosts:
			- h1:
				- ip: h1_ip
				- mac: h1_mac
			- h2:
				...
			...
		"""

		self.current_id = 1
		self.nametable = {}

	
	@set_ev_cls(event.EventHostAdd)
	def _host_add_handler(self, ev):
		dpid = "s" + format(ev.host.port.dpid, "d")
		port_no = ev.host.port.port_no
		mac = ev.host.mac

		self.switches.setdefault(dpid, {})
		self.switches[dpid][port_no] = {"mac":mac, "status":1}

		#print("host_add | switches=", self.switches)
		self.output_dict()


	@set_ev_cls(event.EventPortModify)
	def _port_modify_handler(self, ev):
		dpid = "s" + format(ev.port.dpid, "d")
		port_no = ev.port.port_no
		status = 1 if ev.port.is_live() else 0

		# Se o estado anterior for igual ao atual, não modifica nada
		if (self.switches[dpid][port_no]["status"] == status):
			return
		self.switches[dpid][port_no]["status"] = status

		#print("port_mod | switches=", self.switches)
		self.output_dict()
	
	
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		pkt = packet.Packet(msg.data)

		eth = pkt.get_protocols(ethernet.ethernet)[0]
		ipv = pkt.get_protocols(ipv6.ipv6)[0]

		dpid = "s" + format(datapath.id, "d")
		in_port = msg.match['in_port']
		src_mac = eth.src
		dst_mac = eth.dst
		src_ip = ipv.src
		dst_ip = ipv.dst

		if src_mac in self.nametable:
			hid = self.nametable[src_mac]
		else:
			hid = "h" + format(self.current_id, "d")
			self.current_id += 1
			self.nametable[src_mac] = hid

		self.hosts[hid] = {"mac":src_mac, "ip":src_ip}

		#print("packet_in | hosts=", self.hosts)


	def output_dict(self):

		dic_final = {"switches":self.switches, "hosts":self.hosts}

		#current_time = datetime.now().strftime("%H:%M:%S")
		f = open("topology_" + "test" + ".yaml", "w")
		yaml.dump(dic_final, f)
		#yaml.dump(dic_final, sys.stdout)
		f.close()
	

	@set_ev_cls(event.EventSwitchBase)
	@set_ev_cls(event.EventSwitchEnter)
	@set_ev_cls(event.EventSwitchLeave)
	@set_ev_cls(event.EventSwitchReconnected)
	@set_ev_cls(event.EventPortBase)
	@set_ev_cls(event.EventPortAdd)
	@set_ev_cls(event.EventPortDelete)
	@set_ev_cls(event.EventSwitchRequest)
	@set_ev_cls(event.EventSwitchReply)
	@set_ev_cls(event.EventLinkBase)
	@set_ev_cls(event.EventLinkAdd)
	@set_ev_cls(event.EventLinkDelete)
	@set_ev_cls(event.EventLinkRequest)
	@set_ev_cls(event.EventLinkReply)
	@set_ev_cls(event.EventHostRequest)
	@set_ev_cls(event.EventHostReply)
	@set_ev_cls(event.EventHostBase)
	@set_ev_cls(event.EventHostDelete)
	@set_ev_cls(event.EventHostMove)
	def _print_event_default(self, ev):
		#print(str(ev))
		return
