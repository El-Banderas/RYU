from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, arp
from ryu.ofproto import ofproto_v1_3, ether, inet


IDLE_TIME = 10

WAN_PORT = 1
NAT_PUBLIC_IP = "10.0.10.100"
NAT_PRIVATE_IP = "10.0.10.100"
NAT_PUBLIC_MAC = "10.0.10.100"
NAT_PRIVATE_MAC = "10.0.10.100"

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

		self.current_port = -1 # TODO: Port pool
		self.current_server_idx = -1


	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
				
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
										  ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)
	

	def add_flow(self, datapath, priority, match, actions, idle_timeout=None,
				 buffer_id=None):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
											 actions)]
		if buffer_id and idle_timeout:
			mod = parser.OFPFlowMod(datapath=datapath,
									idle_timeout=idle_timeout,
									buffer_id=buffer_id,
									priority=priority,
									match=match,
									instructions=inst)
		elif not buffer_id and idle_timeout:
			mod = parser.OFPFlowMod(datapath=datapath,
									idle_timeout=idle_timeout,
									priority=priority,
									match=match,
									instructions=inst)
		elif buffer_id and not idle_timeout:
			mod = parser.OFPFlowMod(datapath=datapath,
									buffer_id=buffer_id,
									priority=priority,
									match=match,
									instructions=inst)
		else:
			mod = parser.OFPFlowMod(datapath=datapath,
									priority=priority,
									match=match,
									instructions=inst)
		datapath.send_msg(mod)


	def _get_available_port(self):
		self.current_port += 1
		return self.current_port


	def _get_next_server_ip(self):
		self.current_server_idx += 1
		self.current_server_idx %= len(SERVERS)
		return SERVERS[self.current_server_idx]


	# Flow removido por timeout; porta fica disponível outra vez
	@set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
	def flow_removed_handler(self, ev):
		msg = ev.msg
		tcp_port = msg.match.get('tcp_dst')

		# TODO: re-adicionar porta à port pool


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


	def _private_to_public(self, datapath, buffer_id, data,
						   pkt_ip, pkt_ethernet, pkt_tcp):

		parser = datapath.ofproto_parser
		ofproto = datapath.ofproto

		eth_dst = pkt_ethernet.dst # == NAT_PUBLIC_MAC
		eth_src = pkt_ethernet.src
		ipv4_src = pkt_ip.src
		ipv4_dst = pkt_ip.dst # == NAT_PUBLIC_IP
		tcp_src = pkt_tcp.src_port
		tcp_dst = pkt_tcp.dst_port

		
		nat_port = self._get_available_port()
		target_ip = self._get_next_server_ip()

		nat_eth_dst = IP_TO_MAC_TABLE[target_ip]
		nat_eth_src = NAT_PRIVATE_MAC
		nat_ipv4_src = NAT_PRIVATE_IP
		nat_ipv4_dst = target_ip
		nat_tcp_src = nat_port
		nat_tcp_dst = tcp_dst

		out_port = IP_TO_PORT_TABLE[target_ip]

		match = parser.OFPMatch(in_port=WAN_PORT,
								eth_type=ether.ETH_TYPE_IP,
								ip_proto=inet.IPPROTO_TCP,
								ipv4_src=ipv4_src,
								ipv4_dst=ipv4_dst,
								tcp_src=tcp_src,
								tcp_dst=tcp_dst)

		actions = [	parser.OFPActionSetField(eth_dst=nat_eth_dst),
	     			parser.OFPActionSetField(eth_src=nat_eth_src),
					parser.OFPActionSetField(ipv4_src=nat_ipv4_src),
					parser.OFPActionSetField(ipv4_dst=nat_ipv4_dst),
					parser.OFPActionSetField(tcp_src=nat_tcp_src),
					parser.OFPActionSetField(tcp_dst=nat_tcp_dst),
					parser.OFPActionOutput(out_port)]

		match_back = parser.OFPMatch(	in_port=out_port,
			       						eth_type=ether.ETH_TYPE_IP,
										ip_proto=inet.IPPROTO_TCP,
										ipv4_src=nat_ipv4_dst,
										ipv4_dst=nat_ipv4_src,
										tcp_src=nat_tcp_dst,
										tcp_dst=nat_tcp_src)

		actions_back = [parser.OFPActionSetField(eth_dst=eth_src),
						parser.OFPActionSetField(eth_src=eth_dst),
						parser.OFPActionSetField(ipv4_src=ipv4_dst),
						parser.OFPActionSetField(ipv4_dst=ipv4_src),
						parser.OFPActionSetField(tcp_src=tcp_dst),
						parser.OFPActionSetField(tcp_dst=tcp_src),
						parser.OFPActionOutput(WAN_PORT)]
		

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

		if in_port == self.wan_port:
			# Packets from WAN port
			self._private_to_public(datapath=datapath,
									buffer_id=msg.buffer_id,
									data=msg.data,
									pkt_ethernet=pkt_ethernet,
									pkt_ip=pkt_ip,
									pkt_tcp=pkt_tcp)
		else:
			# Packets from LAN
			pass #TODO: Might be a problem