
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
from array import array

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
		self.macs = {}
		"""
		hosts:
			- h1:
				- ip: h1_ip
				- mac: h1_mac
			- h2:
				...
			...
		"""

	@set_ev_cls(event.EventHostAdd)
	def _host_add_handler(self, ev):

		dpid = ev.host.port.dpid
		port_no = ev.host.port.port_no
		mac = ev.host.mac

		dpid_name = "id"+str(dpid)
		self.hosts.setdefault(dpid_name , {})
		self.hosts[dpid_name][port_no] = {"mac":mac, "status":1}
		self.macs[ev.host.mac] = None
	
	@set_ev_cls(event.EventPortModify)
	def _port_modify_handler(self, ev):
		print("Evento")
		print(ev)
		dpid = ev.port.dpid
		dpid_name = "id"+str(dpid)
		port_no = ev.port.port_no
		status = 1 if ev.port.is_live() else 0
		# Se o estado anterior for igual ao atual, não modifica nada
		if self.hosts[dpid_name][port_no] is not None:
			if (self.hosts[dpid_name][port_no]["status"] == status):
				return 
		self.hosts[dpid_name][port_no]["status"] = status	
		print("------------------")
		print(self.output_dict())
		print("------------------")


	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		msg=ev.msg
		pkt = packet.Packet(ev.msg.data)
		dpid = format(datapath.id, "d").zfill(16)								# int to string & pad 0 à esquerda
		# print(pkt)
		ip= pkt.get_protocol(ipv4.ipv4)
		if ip != None :
			#print(ip)
			srcip = ip.src
			dstip = ip.dst
			
			eth = pkt.get_protocols(ethernet.ethernet)[0]
			'''
			print("IPV4 ", dpid , " -Source ", eth.src, " : ", srcip)
			print("    ", dpid , " - Dest ", eth.dst, " : ", dstip)
			print("Ethernet")
			print(eth)
			'''
			#self.host_map_ip.setdefault(dpid, {})									
			self.macs[eth.src] = srcip
			self.macs[eth.dst] = dstip
			# learn a mac address to avoid FLOOD next time.
			#self.host_map_ip[dpid][srcip] = eth.src
			#self.host_map_ip[dpid][dstip] = eth.dst


	def output_dict(self):

		dic_final = {"switches":self.hosts, "hosts":self.handle_hots_macs_ips()}

		#current_time = datetime.now().strftime("%H:%M:%S")
		now = datetime.now()

		current_time = now.strftime("%H:%M:%S")
		f = open(current_time + ".txt", "a")
		yaml.dump(dic_final, f)
		yaml.dump(dic_final, sys.stdout)
		f.close()
	
	def get_dpid_MAC(self, find_mac):
		for name, entry in self.hosts.items():
			print(name)
			for number_entry, mac_and_status in entry.items():
				print(mac_and_status['mac'])
				print(mac_and_status['mac'] == find_mac)
				if mac_and_status['mac'] == find_mac:
					return name
		return "Unkown"
			

	def handle_hots_macs_ips(self):
		dic_names = {}
		for mac, ip in self.macs.items():
			if ip is None:
				dpid_dwitch = self.get_dpid_MAC(mac)
				dic_names.setdefault(dpid_dwitch, [])									
				list_macs_switch = dic_names[dpid_dwitch] 
				list_macs_switch.append(mac)
				dic_names[dpid_dwitch] = list_macs_switch
			else:
				number_thing = mac[-2:]
				name_thing = "h"+str(number_thing)
				dic_names.setdefault(name_thing, {})									
				dic_names[str(name_thing)]["ip"] = ip 
				dic_names[str(name_thing)]["mac"] = mac 
		return dic_names


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
		#print("Evento")
		#print(ev)
		#print("------------------")
		#print(self.output_dict())
		#print("------------------")
		
		print("------------------")
		dic = self.handle_hots_macs_ips()
		print(dic)
		print("------------------")
		
		return
