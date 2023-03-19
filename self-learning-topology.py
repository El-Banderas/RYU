
from ryu.base import app_manager
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.lib.packet import ethernet, packet, ipv4
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
		dpid_name = "s"+str(dpid)
		port_no = ev.host.port.port_no
		mac = ev.host.mac
		status = 1 if ev.host.port.is_live() else 0

		self.hosts.setdefault(dpid_name , {})
		self.hosts[dpid_name][port_no] = {"mac":mac, "status":status}
		self.macs[ev.host.mac] = None

		self.output_dict()
		return
	
	@set_ev_cls(event.EventPortModify)
	def _port_modify_handler(self, ev):
		dpid = ev.port.dpid
		dpid_name = "s"+str(dpid)
		port_no = ev.port.port_no
		status = 1 if ev.port.is_live() else 0

		# Se o estado anterior for igual ao atual, não modifica nada
		if self.hosts[dpid_name][port_no] is not None:
			if (self.hosts[dpid_name][port_no]["status"] == status):
				return 
		self.hosts[dpid_name][port_no]["status"] = status
		
		self.output_dict()
		return


	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		pkt = packet.Packet(ev.msg.data)
		ip= pkt.get_protocol(ipv4.ipv4)

		if ip != None :
			srcip = ip.src
			dstip = ip.dst

			eth = pkt.get_protocols(ethernet.ethernet)[0]							
			self.macs[eth.src] = srcip
			self.macs[eth.dst] = dstip

			self.output_dict()
		
		return


	def output_dict(self):

		current_time = datetime.now().strftime("%H:%M:%S")
		print("[" + current_time + "] " + "Change in topology detected.")

		dic_final = {"switches":self.hosts, "hosts":self.handle_hots_macs_ips()}
		#print("******")
		#print(dic_final)
		#print("******")

		f = open("topo_" + current_time + ".yml", "w")
		yaml.dump(dic_final, f)
		
		f.close()
		return
	
	def get_dpid_MAC(self, find_mac):
		for name, entry in self.hosts.items():
			for _, mac_and_status in entry.items():
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
