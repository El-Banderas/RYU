
from ryu.base import app_manager
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.lib.packet import ethernet, packet, arp, ipv4, tcp, udp
from ryu.lib.packet import packet

import sys
import ruamel.yaml
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
		self.host_map_ip = {}
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

		self.hosts.setdefault(dpid, {})
		self.hosts[dpid][port_no] = {"mac":mac, "status":1}
		#print("host_add | hosts=", self.hosts)
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
		if (self.hosts[dpid][port_no]["status"] == status):
			return 
		self.hosts[dpid][port_no]["status"] = status
		#print("port_mod | hosts=", self.hosts)
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
		in_port = msg.match['in_port']
		msg=ev.msg
		pkt = packet.Packet(ev.msg.data)
		dpid = format(datapath.id, "d").zfill(16)								# int to string & pad 0 à esquerda
		# print(pkt)
		ip= pkt.get_protocol(ipv4.ipv4)
		if ip != None:
			#print(ip)
			srcip = ip.src
			dstip = ip.dst
			eth = pkt.get_protocols(ethernet.ethernet)[0]
			
			print("IPV4 ", dpid , " -Source ", eth.src, " : ", srcip)
			print("    ", dpid , " - Dest ", eth.dst, " : ", dstip)
			print("Ethernet")
			print(eth)
			self.host_map_ip.setdefault(dpid, {})									

			# learn a mac address to avoid FLOOD next time.
			self.host_map_ip[dpid][srcip] = eth.src
			self.host_map_ip[dpid][dstip] = eth.dst


	def output_dict(self):
		yaml = ruamel.yaml.YAML()  # defaults to round-trip
		#print("YAML")
		dic_final = {}
		current_entryes_number = 0
		for switch_name, switch_devices in self.hosts.items():
			dic_final[switch_name] = clean_switch(switch_devices)
		#print("Final")
		#print(dic_final)
		pkt = packet.Packet(msg.data)

		eth = pkt.get_protocols(ethernet.ethernet)[0]
		#ipv = pkt.get_protocols(ipv6.ipv6)[0]

		dpid = "s" + format(datapath.id, "d")
		in_port = msg.match['in_port']
		src_mac = eth.src
		dst_mac = eth.dst
		#src_ip = ipv.src
		#dst_ip = ipv.dst

		if src_mac in self.nametable:
			hid = self.nametable[src_mac]
		else:
			#hid = "h" + format(self.current_id, "d")
			hid = "h" + src_mac[-2:]
			self.current_id += 1
			self.nametable[src_mac] = hid

		#self.hosts[hid] = {"mac":src_mac, "ip":src_ip}
		self.hosts[hid] = {"mac":src_mac}

		#print("packet_in | hosts=", self.hosts)


	def output_dict(self):

		dic_final = {"switches":self.switches, "hosts":self.hosts}

		#current_time = datetime.now().strftime("%H:%M:%S")
		f = open("topology_" + "test" + ".yaml", "w")
		yaml.dump(dic_final, f)
		#yaml.dump(dic_final, sys.stdout)
		f.close()
	
	@set_ev_cls(event.EventSwitchBase)
	#@set_ev_cls(event.EventSwitchEnter)
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
		print("Evento")
		print(ev)
		print("------------------")
		print(self.host_map_ip)
	
		print("------------------")
