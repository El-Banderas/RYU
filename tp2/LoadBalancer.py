from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, arp
from ryu.ofproto import ofproto_v1_3, ether, inet


IDLE_TIME = 10

WAN_PORT = 1
LB_IP = "10.0.10.100"
LB_MAC = "00:00:00:00:01:00"

SERVERS = ["10.0.10.101", "10.0.10.102", "10.0.10.103"]
IP_TO_MAC_TABLE = {
	"10.0.10.101": '00:00:00:00:01:01',
	"10.0.10.102": '00:00:00:00:01:02',
	"10.0.10.103": '00:00:00:00:01:03'
}
IP_TO_PORT_TABLE = {
	"10.0.10.101": 3,
	"10.0.10.102": 4,
	"10.0.10.103": 2
}
	

class LoadBalancer(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(LoadBalancer, self).__init__(*args, **kwargs)
		
		self.mac_to_port = {}
		self.matches = {}

		self.current_server_idx = -1
		self.active_connections = {server: 0 for server in SERVERS}




	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
				
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
										  ofproto.OFPCML_NO_BUFFER)]
		self._add_flow(datapath, priority=0, match=match, actions=actions)


	
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		in_port = msg.match['in_port']
		pkt = packet.Packet(msg.data)

		pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
		pkt_arp = pkt.get_protocol(arp.arp)
		pkt_ip = pkt.get_protocol(ipv4.ipv4)
		pkt_tcp = pkt.get_protocol(tcp.tcp)


		if (in_port == WAN_PORT and pkt_ip and pkt_tcp):
			# Packets from WAN port (& fluxo normal)

			if pkt_tcp.has_flags(tcp.TCP_SYN): 
				# New session
				self._public_to_private(datapath=datapath,
										buffer_id=msg.buffer_id,
										data=msg.data,
										pkt_ethernet=pkt_ethernet,
										pkt_ip=pkt_ip,
										pkt_tcp=pkt_tcp)

			elif pkt_tcp.has_flags(tcp.TCP_FIN) and (pkt_ip.src, pkt_tcp.src_port) in self.matches:
				# End session
				self._end_connection(datapath=datapath,
									buffer_id=msg.buffer_id,
									data=msg.data,
									pkt_ethernet=pkt_ethernet,
									pkt_ip=pkt_ip,
									pkt_tcp=pkt_tcp)
				
			elif pkt_tcp.has_flags(tcp.TCP_FIN):
				print("\n[WARN] Recebe um FIN mas não está no dicionário\n")
				
			else:
				print("\n[WARN] Recebeu um pacote TCP estranho")
				print_flags(pkt_tcp)


		elif (in_port == WAN_PORT and pkt_arp and pkt_arp.opcode == arp.ARP_REQUEST):
			# ARP requests
			self._arp_request_handler(datapath, pkt_arp)


		else:
			# Packets from LAN
			self._packet_in_handler_default(ev)



	def _public_to_private(self, datapath, buffer_id, data,
						   pkt_ip, pkt_ethernet, pkt_tcp):

		parser = datapath.ofproto_parser
		ofproto = datapath.ofproto
		
		public_eth_src = pkt_ethernet.src
		public_eth_dst = pkt_ethernet.dst # == LB_MAC?
		public_ipv4_src = pkt_ip.src
		public_ipv4_dst = pkt_ip.dst # == LB_IP?
		public_tcp_src = pkt_tcp.src_port
		public_tcp_dst = pkt_tcp.dst_port

		target_ip = self._get_next_server_ip(); self.active_connections[target_ip] += 1
		target_mac = IP_TO_MAC_TABLE[target_ip]
		out_port = IP_TO_PORT_TABLE[target_ip]

		private_eth_src = public_eth_src
		private_eth_dst = target_mac
		private_ipv4_src = public_ipv4_src
		private_ipv4_dst = target_ip
		private_tcp_src = public_tcp_src
		private_tcp_dst = public_tcp_dst

		print("\nRecebeu um SYN:")
		print_flags(pkt_tcp=pkt_tcp)
		print(
		f"eth_src: {public_eth_src} -> {private_eth_src}\n"
		f"eth_dst: {public_eth_dst} -> {private_eth_dst}\n"
		f"ipv4_src: {public_ipv4_src} -> {private_ipv4_src}\n"
		f"ipv4_dst: {public_ipv4_dst} -> {private_ipv4_dst}\n"
		f"tcp_src: {public_tcp_src} -> {private_tcp_src}\n"
		f"tcp_dst: {public_tcp_dst} -> {private_tcp_dst}"
		)
		

		last_match_with_Ack = parser.OFPMatch(
								in_port=out_port,
								eth_type=ether.ETH_TYPE_IP,
								ip_proto=inet.IPPROTO_TCP,
								ipv4_src=private_ipv4_dst,
								ipv4_dst=private_ipv4_src,
								tcp_flags=tcp.TCP_ACK,
								)
		match = parser.OFPMatch(
								in_port=WAN_PORT,
								eth_type=ether.ETH_TYPE_IP,
								ip_proto=inet.IPPROTO_TCP,
								ipv4_src=public_ipv4_src,
								ipv4_dst=public_ipv4_dst,
								tcp_src=public_tcp_src,
								)
		match_back = parser.OFPMatch(	
								in_port=out_port,
								eth_type=ether.ETH_TYPE_IP,
								ip_proto=inet.IPPROTO_TCP,
								ipv4_src=private_ipv4_dst,
								ipv4_dst=private_ipv4_src,
								tcp_dst=private_tcp_src,
								)
		match_fin = parser.OFPMatch(
								in_port=WAN_PORT,
								eth_type=ether.ETH_TYPE_IP,
								ip_proto=inet.IPPROTO_TCP,
								ipv4_src=public_ipv4_src,
								ipv4_dst=public_ipv4_dst,
								tcp_flags=tcp.TCP_ACK|tcp.TCP_FIN,
								)


		actions = [
					parser.OFPActionSetField(eth_dst=private_eth_dst),
	     			parser.OFPActionSetField(eth_src=private_eth_src),
					parser.OFPActionSetField(ipv4_src=private_ipv4_src),
					parser.OFPActionSetField(ipv4_dst=private_ipv4_dst),
					parser.OFPActionOutput(out_port)
				]

		actions_back = [
					parser.OFPActionSetField(eth_dst=public_eth_src),
					parser.OFPActionSetField(eth_src=public_eth_dst),
					parser.OFPActionSetField(ipv4_src=public_ipv4_dst),
					parser.OFPActionSetField(ipv4_dst=public_ipv4_src),
					parser.OFPActionOutput(WAN_PORT)
				]
		

		self.matches[(public_ipv4_src, public_tcp_src)] = (match, match_back, last_match_with_Ack, actions, actions_back, match_fin)
		actions_manda_controlador = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
										  ofproto.OFPCML_NO_BUFFER)]

	    # É do cliente para o servidor, logo é o normal, NÃO O BACK
		self._add_flow(datapath, match=match_fin, actions=actions_manda_controlador , priority=15)
		self._add_flow(datapath, match=match, actions=actions, priority=10)
		self._add_flow(datapath, match=match_back, actions=actions_back, priority=10)


		d = None
		if buffer_id == ofproto.OFP_NO_BUFFER:
			d = data

		out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
								  in_port=WAN_PORT, actions=actions, data=d)
		datapath.send_msg(out)



	def _end_connection(self, datapath, buffer_id, data,
						pkt_ip, pkt_ethernet, pkt_tcp):
		parser = datapath.ofproto_parser
		ofproto = datapath.ofproto
		
		#self.active_connections[pkt_ip.dst] -= 1 #TODO
		(last_match, last_match_back, last_match_with_Ack, last_action, last_action_back, match_fin) = self.matches[(pkt_ip.src, pkt_tcp.src_port)] 
		
		print("\nRecebeu um FIN:")
		print_flags(pkt_tcp=pkt_tcp); print()
		#print(last_match)
		#print(last_match_back)
		#print(last_match_with_Ack)
		#print(last_action)
		#print(last_action_back)

		# Apagar os flows 
		mod1 = parser.OFPFlowMod(datapath=datapath, match=last_match, cookie=0,out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,flags=ofproto.OFPFF_SEND_FLOW_REM,command=ofproto.OFPFC_DELETE)
		mod2 = parser.OFPFlowMod(datapath=datapath, match=last_match_back, cookie=0,out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,flags=ofproto.OFPFF_SEND_FLOW_REM,command=ofproto.OFPFC_DELETE)
		datapath.send_msg(mod1)	
		datapath.send_msg(mod2)	

		self._add_flow(datapath, match=last_match_with_Ack, idle_timeout=2, actions=last_action_back , priority=20)

		# Enviar a mensagem que recebeu para o servidor
		d = None
		if buffer_id == ofproto.OFP_NO_BUFFER:
			d = data
		out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
								  in_port=WAN_PORT, actions=last_action, data=d)

		datapath.send_msg(out)



	# send ARP reply
	def _arp_request_handler(self, datapath, pkt_arp):
		parser = datapath.ofproto_parser
		ofproto = datapath.ofproto

		e = ethernet.ethernet(pkt_arp.src_mac, LB_MAC, ether_types.ETH_TYPE_ARP)
		a = arp.arp(1, 0x0800, 6, 4, arp.ARP_REQUEST, LB_MAC, LB_IP, pkt_arp.src_mac, pkt_arp.src_ip)
		p = packet.Packet()
		p.add_protocol(e)
		p.add_protocol(a)
		p.serialize()
		
		actions = [parser.OFPActionOutput(ofproto.OFPP_IN_PORT)]
		out = parser.OFPPacketOut(
			datapath=datapath,
			buffer_id=ofproto.OFP_NO_BUFFER,
			in_port=WAN_PORT,
			actions=actions,
			data=p.data
        )
		datapath.send_msg(out)



	# simple switch handler
	def _packet_in_handler_default(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		in_port = msg.match['in_port']

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocol(ethernet.ethernet)

		dst = eth.dst
		src = eth.src


		# learn a mac address to avoid FLOOD next time.
		self.mac_to_port[src] = in_port


		if dst in self.mac_to_port:
			out_port = self.mac_to_port[dst]
		else:
			out_port = ofproto.OFPP_FLOOD

		actions = [parser.OFPActionOutput(out_port)]


		# install a flow to avoid packet_in next time
		if out_port != ofproto.OFPP_FLOOD:

			match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, eth_type=ether_types.ETH_TYPE_ARP)

			if msg.buffer_id != ofproto.OFP_NO_BUFFER:
				self._add_flow(datapath, priority=1, match=match, actions=actions, buffer_id=msg.buffer_id)
				return
			else:
				self._add_flow(datapath, priority=1, match=match, actions=actions)

		data = None
		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
			data = msg.data

		out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
								  in_port=in_port, actions=actions, data=data)
	
		datapath.send_msg(out)



	#"""
	def _get_next_server_ip(self):
		self.current_server_idx += 1
		self.current_server_idx %= len(SERVERS)
		return SERVERS[self.current_server_idx]
	"""
	def _get_next_server_ip(self):
		conns = self.active_connections
		least_active = min(conns, key=conns.get)
		return least_active
	"""



	def _add_flow(self, datapath, table_id=0, idle_timeout=0, hard_timeout=0, priority=32768, buffer_id=4294967295, match=None, actions=None):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		if not match or not actions:
			print("[ERROR] Tried to add invalid flow!")
			return

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]

		mod = parser.OFPFlowMod(datapath=datapath,
								table_id=table_id,
								idle_timeout=idle_timeout,
								hard_timeout=hard_timeout,
								priority=priority,
								buffer_id=buffer_id,
								match=match,
								instructions=inst)
		datapath.send_msg(mod)



	def _send_packet_to_port(self, datapath, port, data):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		actions = [parser.OFPActionOutput(port=port)]

		out = parser.OFPPacketOut(datapath=datapath,
								  buffer_id=ofproto.OFP_NO_BUFFER,
								  in_port=ofproto.OFPP_CONTROLLER,
								  actions=actions,
								  data=data)
		datapath.send_msg(out)
	



def print_flags(pkt_tcp):
	flags = {
		tcp.TCP_SYN: "TCP_SYN",
		tcp.TCP_RST: "TCP_RST",
		tcp.TCP_PSH: "TCP_PSH",
		tcp.TCP_ACK: "TCP_ACK",
		tcp.TCP_URG: "TCP_URG",
		tcp.TCP_ECE: "TCP_ECE",
		tcp.TCP_CWR: "TCP_CWR",
		tcp.TCP_NS:  "TCP_NS",
		tcp.TCP_FIN: "TCP_FIN",
	}
	for flag in flags:
		if pkt_tcp.has_flags(flag):
			print("-> " + flags[flag])