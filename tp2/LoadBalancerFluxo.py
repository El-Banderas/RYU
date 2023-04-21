from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, packet_base, ethernet, ether_types, ipv4, tcp, arp
from ryu.ofproto import ofproto_v1_3, ether, inet


IDLE_TIME = 4

WAN_PORT = 1
NAT_PUBLIC_IP = "10.0.10.100"
NAT_PRIVATE_IP = "10.0.10.100"
NAT_PUBLIC_MAC = "00:00:00:00:01:00"
NAT_PRIVATE_MAC = "00:00:00:00:01:00"

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
		self.current_server_idx = -1



	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
				
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
										  ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, priority=0, match=match, actions=actions)



	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']
		pkt = packet.Packet(msg.data)

		pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
		pkt_arp = pkt.get_protocol(arp.arp)
		pkt_ip = pkt.get_protocol(ipv4.ipv4)
		pkt_tcp = pkt.get_protocol(tcp.tcp)

		if (in_port == WAN_PORT and pkt_ip and pkt_tcp):
			# Packets from WAN port (& fluxo normal)
			self._public_to_private(datapath=datapath,
									buffer_id=msg.buffer_id,
									data=msg.data,
									pkt_ethernet=pkt_ethernet,
									pkt_ip=pkt_ip,
									pkt_tcp=pkt_tcp)

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
		public_eth_dst = pkt_ethernet.dst # == NAT_PUBLIC_MAC (TODO)
		public_ipv4_src = pkt_ip.src
		public_ipv4_dst = pkt_ip.dst # == NAT_PUBLIC_IP (TODO)
		public_tcp_src = pkt_tcp.src_port
		public_tcp_dst = pkt_tcp.dst_port

		
		target_ip = self._get_next_server_ip()
		target_mac = IP_TO_MAC_TABLE[target_ip]
		out_port = IP_TO_PORT_TABLE[target_ip]

		#TODO:
		"""
		nat_eth_src = NAT_PRIVATE_MAC
		nat_eth_dst = IP_TO_MAC_TABLE[target_ip]
		nat_ipv4_src = NAT_PRIVATE_IP
		nat_ipv4_dst = target_ip
		nat_tcp_src = nat_port
		nat_tcp_dst = tcp_dst
		"""

		private_eth_src = public_eth_src
		private_eth_dst = target_mac
		private_ipv4_src = public_ipv4_src
		private_ipv4_dst = target_ip
		private_tcp_src = public_tcp_src
		private_tcp_dst = public_tcp_dst


		print(
		"\n\n"
		f"eth_src: {public_eth_src} -> {private_eth_src}\n"
		f"eth_dst: {public_eth_dst} -> {private_eth_dst}\n"
		f"ipv4_src: {public_ipv4_src} -> {private_ipv4_src}\n"
		f"ipv4_dst: {public_ipv4_dst} -> {private_ipv4_dst}\n"
		f"tcp_src: {public_tcp_src} -> {private_tcp_src}\n"
		f"tcp_dst: {public_tcp_dst} -> {private_tcp_dst}\n"
		)
		print("TCP flags (SYN, ACK, FIN)")
		print(pkt_tcp.has_flags(tcp.TCP_SYN))
		print(pkt_tcp.has_flags(tcp.TCP_ACK))
		print(pkt_tcp.has_flags(tcp.TCP_FIN))


		match = parser.OFPMatch(
								in_port=WAN_PORT,
								eth_type=ether.ETH_TYPE_IP,
								ip_proto=inet.IPPROTO_TCP,
								ipv4_src=public_ipv4_src,
								ipv4_dst=public_ipv4_dst,
								tcp_src=public_tcp_src,
								tcp_dst=public_tcp_dst,
								)

		actions = [
					parser.OFPActionSetField(eth_dst=private_eth_dst),
	     			parser.OFPActionSetField(eth_src=private_eth_src),
					parser.OFPActionSetField(ipv4_src=private_ipv4_src),
					parser.OFPActionSetField(ipv4_dst=private_ipv4_dst),
					parser.OFPActionSetField(tcp_src=private_tcp_src),
					parser.OFPActionSetField(tcp_dst=private_tcp_dst),
					parser.OFPActionOutput(out_port)
					]

		match_back = parser.OFPMatch(	
									in_port=out_port,
									eth_type=ether.ETH_TYPE_IP,
									ip_proto=inet.IPPROTO_TCP,
									ipv4_src=private_ipv4_dst,
									ipv4_dst=private_ipv4_src,
									tcp_src=private_tcp_dst,
									tcp_dst=private_tcp_src
									)

		actions_back = [
						parser.OFPActionSetField(eth_dst=public_eth_src),
						parser.OFPActionSetField(eth_src=public_eth_dst),
						parser.OFPActionSetField(ipv4_src=public_ipv4_dst),
						parser.OFPActionSetField(ipv4_dst=public_ipv4_src),
						parser.OFPActionSetField(tcp_src=public_tcp_dst),
						parser.OFPActionSetField(tcp_dst=public_tcp_src),
						parser.OFPActionOutput(WAN_PORT)
						]
		

		self.add_flow(datapath, match=match, actions=actions,
					  idle_timeout=IDLE_TIME, priority=10)
		self.add_flow(datapath, match=match_back, actions=actions_back,
					  idle_timeout=IDLE_TIME, priority=10)

		d = None
		if buffer_id == ofproto.OFP_NO_BUFFER:
			d = data

		out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
								  in_port=WAN_PORT, actions=actions, data=d)
		datapath.send_msg(out)



	# send ARP reply
	def _arp_request_handler(self, datapath, pkt_arp):
		parser = datapath.ofproto_parser
		ofproto = datapath.ofproto

		e = ethernet.ethernet(pkt_arp.src_mac, NAT_PUBLIC_MAC, ether_types.ETH_TYPE_ARP)
		a = arp.arp(1, 0x0800, 6, 4, arp.ARP_REQUEST, NAT_PUBLIC_MAC, NAT_PUBLIC_IP, pkt_arp.src_mac, pkt_arp.src_ip)
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
				self.add_flow(datapath, priority=1, match=match, actions=actions, buffer_id=msg.buffer_id)
				return
			else:
				self.add_flow(datapath, priority=1, match=match, actions=actions)

		data = None
		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
			data = msg.data

		out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
								  in_port=in_port, actions=actions, data=data)
	
		datapath.send_msg(out)



	def _get_next_server_ip(self):
		self.current_server_idx += 1
		self.current_server_idx %= len(SERVERS)
		return SERVERS[self.current_server_idx]



	def add_flow(self, datapath, table_id=0, idle_timeout=0, hard_timeout=0, priority=32768, buffer_id=4294967295, match=None, actions=None):
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