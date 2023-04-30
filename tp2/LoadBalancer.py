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

def print_flags(pkt_tcp):
		lista_flags = [tcp.TCP_SYN,tcp.TCP_RST,tcp.TCP_PSH,tcp.TCP_ACK,tcp.TCP_URG,tcp.TCP_ECE,tcp.TCP_CWR,tcp.TCP_NS, tcp.TCP_FIN ]
		lista_flags_nomes = ["TCP_SYN","tcp.TCP_RST","tcp.TCP_PSH","tcp.TCP_ACK","tcp.TCP_URG","tcp.TCP_ECE","tcp.TCP_CWR","tcp.TCP_NS", "tcp.TCP_FIN" ]
		for (idx, flag) in enumerate(lista_flags):
			if 	pkt_tcp.has_flags(flag):
				print("Flag true " , flag )
				print("Flag true " , lista_flags_nomes[idx] )
	

class LoadBalancer(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(LoadBalancer, self).__init__(*args, **kwargs)
		
		self.mac_to_port = {}

		self.current_port = -1 # TODO: Port pool
		'''
		self.last_match = None
		self.last_match_with_Ack = None
		self.last_match_back = None
		self.last_action = None
		self.last_action_back = None
		'''
		self.dic_match_stuff = {}

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

		print("flow removed: " + ev)

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


	def _public_to_private(self, datapath, buffer_id, data,
						   pkt_ip, pkt_ethernet, pkt_tcp):

		parser = datapath.ofproto_parser
		ofproto = datapath.ofproto
		
		eth_src = pkt_ethernet.src
		eth_dst = pkt_ethernet.dst # == NAT_PUBLIC_MAC
		ipv4_src = pkt_ip.src
		ipv4_dst = pkt_ip.dst # == NAT_PUBLIC_IP
		tcp_src = pkt_tcp.src_port
		tcp_dst = pkt_tcp.dst_port

		
		nat_port = self._get_available_port()
		target_ip = self._get_next_server_ip()

		"""
		nat_eth_src = NAT_PRIVATE_MAC
		nat_eth_dst = IP_TO_MAC_TABLE[target_ip]
		nat_ipv4_src = NAT_PRIVATE_IP
		nat_ipv4_dst = target_ip
		nat_tcp_src = nat_port
		nat_tcp_dst = tcp_dst
		"""

		nat_eth_src = eth_src
		nat_eth_dst = IP_TO_MAC_TABLE[target_ip]
		nat_ipv4_src = ipv4_src
		nat_ipv4_dst = target_ip
		nat_tcp_src = tcp_src
		nat_tcp_dst = tcp_dst

		out_port = IP_TO_PORT_TABLE[target_ip]

		print(
			f"""
			eth_src: {eth_src} -> {nat_eth_src}
			eth_dst: {eth_dst} -> {nat_eth_dst}
			ipv4_src: {ipv4_src} -> {nat_ipv4_src}
			ipv4_dst: {ipv4_dst} -> {nat_ipv4_dst}
			tcp_src: {tcp_src} -> {nat_tcp_src}
			tcp_dst: {tcp_dst} -> {nat_tcp_dst}
			"""
		)
		lista_flags = [tcp.TCP_SYN,tcp.TCP_RST,tcp.TCP_PSH,tcp.TCP_ACK,tcp.TCP_URG,tcp.TCP_ECE,tcp.TCP_CWR,tcp.TCP_NS, tcp.TCP_FIN ]
		lista_flags_nomes = ["TCP_SYN","tcp.TCP_RST","tcp.TCP_PSH","tcp.TCP_ACK","tcp.TCP_URG","tcp.TCP_ECE","tcp.TCP_CWR","tcp.TCP_NS", "tcp.TCP_FIN" ]
		for (idx, flag) in enumerate(lista_flags):
			if 	pkt_tcp.has_flags(flag):
				print("Flag true " , flag )
				print("Flag true " , lista_flags_nomes[idx] )
		'''
		print("TCP flags (SYN, ACK, FIN)")
		print(pkt_tcp.has_flags(tcp.TCP_SYN))
		print(pkt_tcp.has_flags(tcp.TCP_ACK))
		print(pkt_tcp.has_flags(tcp.TCP_FIN))
		'''
		last_match_with_Ack = parser.OFPMatch(
								
									in_port=out_port,
									eth_type=ether.ETH_TYPE_IP,
									ip_proto=inet.IPPROTO_TCP,
									ipv4_src=nat_ipv4_dst,
									ipv4_dst=nat_ipv4_src,
								tcp_flags=tcp.TCP_ACK,
								)
		match = parser.OFPMatch(
								in_port=WAN_PORT,
								eth_type=ether.ETH_TYPE_IP,
								ip_proto=inet.IPPROTO_TCP,
								ipv4_src=ipv4_src,
								ipv4_dst=ipv4_dst,
								tcp_src=tcp_src,
								#tcp_dst=tcp_dst,
								# Vi as flags daqui:
								# https://github.com/faucetsdn/ryu/blob/e3ebed794332ca23a0f67580fd3230612d9d7b07/ryu/lib/packet/tcp.py#L42
								#tcp_flags=tcp.TCP_ACK|tcp.TCP_PSH,
								)
		match_fin = parser.OFPMatch(
								in_port=WAN_PORT,
								eth_type=ether.ETH_TYPE_IP,
								ip_proto=inet.IPPROTO_TCP,
								ipv4_src=ipv4_src,
								ipv4_dst=ipv4_dst,
								#tcp_src=tcp_src,
								#tcp_dst=tcp_dst,
								tcp_flags=tcp.TCP_ACK|tcp.TCP_FIN,
								#tcp_flags=tcp.TCP_FIN
								)


		actions = [
					parser.OFPActionSetField(eth_dst=nat_eth_dst),
	     			parser.OFPActionSetField(eth_src=nat_eth_src),
					parser.OFPActionSetField(ipv4_src=nat_ipv4_src),
					parser.OFPActionSetField(ipv4_dst=nat_ipv4_dst),
					#parser.OFPActionSetField(tcp_src=nat_tcp_src),
					#parser.OFPActionSetField(tcp_dst=nat_tcp_dst),
					parser.OFPActionOutput(out_port)
					]
		match_back = parser.OFPMatch(	
									in_port=out_port,
									eth_type=ether.ETH_TYPE_IP,
									ip_proto=inet.IPPROTO_TCP,
									ipv4_src=nat_ipv4_dst,
									ipv4_dst=nat_ipv4_src,
									#tcp_src=nat_tcp_dst,
									tcp_dst=nat_tcp_src,
									#tcp_flags=tcp.TCP_ACK|tcp.TCP_SYN,
									)

		actions_back = [
						parser.OFPActionSetField(eth_dst=eth_src),
						parser.OFPActionSetField(eth_src=eth_dst),
						parser.OFPActionSetField(ipv4_src=ipv4_dst),
						parser.OFPActionSetField(ipv4_dst=ipv4_src),
						#parser.OFPActionSetField(tcp_src=tcp_dst),
						#parser.OFPActionSetField(tcp_dst=tcp_src),
						parser.OFPActionOutput(WAN_PORT)
						]
		'''
		self.last_match = match
		self.last_match_back = match_back
		self.last_match_with_Ack = last_match_with_Ack
		self.last_action = actions
		self.last_action_back = actions_back
		'''
		self.dic_match_stuff[(ipv4_src, tcp_src)] = (match, match_back, last_match_with_Ack, actions, actions_back, match_fin)
		actions_manda_controlador = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
										  ofproto.OFPCML_NO_BUFFER)]

	    # É do cliente para o servidor, logo é o normal, NÃO O BACK
		self.add_flow(datapath, match=match_fin, actions=actions_manda_controlador , priority=15)
		self.add_flow(datapath, match=match, actions=actions, priority=10)
		self.add_flow(datapath, match=match_back, actions=actions_back, priority=10)

		d = None
		if buffer_id == ofproto.OFP_NO_BUFFER:
			d = data

		out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
								  in_port=WAN_PORT, actions=actions, data=d)
		datapath.send_msg(out)

	def end_connection(self, datapath, buffer_id, data,
						   pkt_ip, pkt_ethernet, pkt_tcp):
		parser = datapath.ofproto_parser
		ofproto = datapath.ofproto
		
		ipv4_src = pkt_ip.src
		tcp_src = pkt_tcp.src_port
		(last_match, last_match_back, last_match_with_Ack, last_action, last_action_back, match_fin) = self.dic_match_stuff[(ipv4_src, tcp_src)] 
		print("Recebeu um fin")
		print(last_match)
		print(last_match_back)
		print(last_match_with_Ack)
		print(last_action)
		print(last_action_back)
		lista_flags = [tcp.TCP_SYN,tcp.TCP_RST,tcp.TCP_PSH,tcp.TCP_ACK,tcp.TCP_URG,tcp.TCP_ECE,tcp.TCP_CWR,tcp.TCP_NS, tcp.TCP_FIN ]
		del self.dic_match_stuff[(ipv4_src, tcp_src)]
		lista_flags_nomes = ["TCP_SYN","tcp.TCP_RST","tcp.TCP_PSH","tcp.TCP_ACK","tcp.TCP_URG","tcp.TCP_ECE","tcp.TCP_CWR","tcp.TCP_NS", "tcp.TCP_FIN" ]
		for (idx, flag) in enumerate(lista_flags):
			if 	pkt_tcp.has_flags(flag):
				print("Flag true " , flag )
				print("Flag true " , lista_flags_nomes[idx] )
		# Apagar os flows 
		mod1 = parser.OFPFlowMod(datapath=datapath, match=last_match, cookie=0,out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,flags=ofproto.OFPFF_SEND_FLOW_REM,command=ofproto.OFPFC_DELETE)
		mod2 = parser.OFPFlowMod(datapath=datapath, match=last_match_back, cookie=0,out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,flags=ofproto.OFPFF_SEND_FLOW_REM,command=ofproto.OFPFC_DELETE)
		mod3 = parser.OFPFlowMod(datapath=datapath, match=match_fin, cookie=0,out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,flags=ofproto.OFPFF_SEND_FLOW_REM,command=ofproto.OFPFC_DELETE)
		datapath.send_msg(mod1)	
		datapath.send_msg(mod2)	
		self.add_flow(datapath, match=last_match_with_Ack, idle_timeout=2, actions=last_action_back , priority=20)
		# Enviar a mensagem que recebeu para o servidor
		d = None
		if buffer_id == ofproto.OFP_NO_BUFFER:
			d = data
		out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
								  in_port=WAN_PORT, actions=last_action, data=d)

		datapath.send_msg(out)
		#datapath.send_msg(mod3)	
		# Depois saber reencaminhar o ACK

	
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']
		pkt = packet.Packet(msg.data)

		pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
		#pkt_arp = pkt.get_protocol(arp.arp)
		pkt_ip = pkt.get_protocol(ipv4.ipv4)
		pkt_tcp = pkt.get_protocol(tcp.tcp)


		if (pkt_ip and pkt_tcp and in_port == WAN_PORT):
			ipv4_src = pkt_ip.src
			tcp_src = pkt_tcp.src_port
			if pkt_tcp.has_flags(tcp.TCP_FIN) and (ipv4_src, tcp_src) in self.dic_match_stuff:
				self.end_connection(datapath=datapath,
										buffer_id=msg.buffer_id,
										data=msg.data,
										pkt_ethernet=pkt_ethernet,
									pkt_ip=pkt_ip,
									pkt_tcp=pkt_tcp)
			elif pkt_tcp.has_flags(tcp.TCP_FIN):
				print("Recebe um FIN mas não está no dicionário. Estranho...")
			elif pkt_tcp.has_flags(tcp.TCP_SYN): 
				# Packets from WAN port (& fluxo normal)
				self._public_to_private(datapath=datapath,
										buffer_id=msg.buffer_id,
										data=msg.data,
										pkt_ethernet=pkt_ethernet,
									pkt_ip=pkt_ip,
									pkt_tcp=pkt_tcp)
			else:
				print("recebeu um pacote tcp estranho")
				print_flags(pkt_tcp)
		else:
			# Packets from LAN
			self._packet_in_handler_default(ev)


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
			
		#self.logger.info("packet_in | src=%s dst=%s in_port=%s out_port=%s", src, dst, in_port, out_port)

		actions = [parser.OFPActionOutput(out_port)]

		# install a flow to avoid packet_in next time
		if out_port != ofproto.OFPP_FLOOD:
			match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, eth_type=ether_types.ETH_TYPE_ARP)
			if msg.buffer_id != ofproto.OFP_NO_BUFFER:
				self.add_flow(datapath, 1, match, actions, msg.buffer_id)
				return
			else:
				self.add_flow(datapath, 1, match, actions)
		data = None
		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
			data = msg.data

		out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
								  in_port=in_port, actions=actions, data=data)
	
		datapath.send_msg(out)


