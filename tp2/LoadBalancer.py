from ryu.base import app_manager
from ryu.app.wsgi import ControllerBase, WSGIApplication
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, arp
from ryu.ofproto import ofproto_v1_3, ether, inet
from netaddr import IPNetwork, IPAddress



IDLE_TIME = 10

class LoadBalancer(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(LoadBalancer, self).__init__(*args, **kwargs)
				
		self.nat_settings = settings.load()

		self.wan_port = nat_settings['wan_port']

		self.gateway = str(nat_settings['default_gateway'])

		self.nat_public_ip = str(nat_settings['nat_public_ip'])
		self.nat_private_ip = nat_settings['dhcp_gw_addr']

		self.private_subnetwork = nat_settings['ip_network']

		self.MAC_ON_WAN = nat_settings['MAC_ON_WAN']
		self.MAC_ON_LAN = nat_settings['MAC_ON_LAN']

		self.current_port = -1 # TODO: Port pool


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


	# Flow removido por timeout; porta fica disponível outra vez
	@set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
	def flow_removed_handler(self, ev):
		
		msg = ev.msg
		tcp_port = msg.match.get('tcp_dst')

		# TODO

	def _send_packet_to_port(self, datapath, port, data):
		if data is None:
			# Do NOT sent when data is None
			return
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		actions = [parser.OFPActionOutput(port=port)]
		# self.logger.info("packet-out %s" % (data,))
		out = parser.OFPPacketOut(datapath=datapath,
								  buffer_id=ofproto.OFP_NO_BUFFER,
								  in_port=ofproto.OFPP_CONTROLLER,
								  actions=actions,
								  data=data)
		datapath.send_msg(out)


	def _arp_request_handler(self, pkt_arp):

		data = None

		if pkt_arp.dst_ip == str(self.nat_private_ip):
			# Who has 192.168.8.1 ?
			# Tell 192.168.8.20(Host),
			# 192.168.8.1's fake MAC address (eth1)
			data = nat_helper.arp_reply(src_mac=self.MAC_ON_LAN,
										src_ip=str(self.nat_private_ip),
										target_mac=pkt_arp.src_mac,
										target_ip=pkt_arp.src_ip)

		elif pkt_arp.dst_ip == self.nat_public_ip:
			# Who has 140.114.71.176 ?
			# Tell 140.114.71.xxx(Extranet Network host)
			data = nat_helper.arp_reply(src_mac=self.MAC_ON_WAN,
										src_ip=self.nat_public_ip,
										target_mac=pkt_arp.src_mac,
										target_ip=pkt_arp.src_ip)

		return data

	def _arp_reply_handler(self, pkt_arp):
		if pkt_arp.opcode != arp.ARP_REPLY:
			print('[WARRING] Wrong ARP opcode!')
			return None

		if pkt_arp.dst_ip == self.nat_public_ip:
			IP_TO_MAC_TABLE[pkt_arp.src_ip] = pkt_arp.src_mac

	def _in_nat_public_ip_subnetwork(self, ip):
		ip = IPAddress(ip)
		if ip in IPNetwork('127.0.0.0/24'):
			return True
		else:
			return False

	def _in_private_subnetwork(self, ip):
		ip = IPAddress(ip)
		return ip in self.private_subnetwork

	def _is_public(self, ip):
		ip = IPAddress(ip)
		return ip.is_unicast() and not ip.is_private()

	def _private_to_public(self, datapath, buffer_id, data, in_port, out_port,
						   pkt_ip, pkt_ethernet, pkt_tcp=None, pkt_udp=None,
						   pkt_icmp=None):
		if pkt_ip is None:
			return

		parser = datapath.ofproto_parser
		ofproto = datapath.ofproto

		# eth_dst = pkt_ethernet.dst
		eth_src = pkt_ethernet.src
		ipv4_src = pkt_ip.src
		ipv4_dst = pkt_ip.dst

		nat_port = self._get_available_port()

		if (self._is_public(ipv4_dst) and not self._in_nat_public_ip_subnetwork(ipv4_dst)):
			target_ip = self.gateway
		elif self._in_nat_public_ip_subnetwork(ipv4_dst):
			target_ip = ipv4_dst
		elif self._in_private_subnetwork(ipv4_dst):
			return

		if pkt_tcp:
			# print "@@@ Install TCP Flow Entry @@@"
			tcp_src = pkt_tcp.src_port
			tcp_dst = pkt_tcp.dst_port

			match = parser.OFPMatch(in_port=in_port,
									eth_type=ether.ETH_TYPE_IP,
									ip_proto=inet.IPPROTO_TCP,
									ipv4_src=ipv4_src,
									ipv4_dst=ipv4_dst,
									tcp_src=tcp_src,
									tcp_dst=tcp_dst)

			actions = [parser.OFPActionSetField(eth_dst=IP_TO_MAC_TABLE[target_ip]),
					   parser.OFPActionSetField(ipv4_src=self.nat_public_ip),
					   parser.OFPActionSetField(tcp_src=nat_port),
					   parser.OFPActionOutput(out_port)]

			match_back = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
										 ip_proto=inet.IPPROTO_TCP,
										 ipv4_src=ipv4_dst,
										 ipv4_dst=self.nat_public_ip,
										 tcp_src=tcp_dst,
										 tcp_dst=nat_port)

			actions_back = [parser.OFPActionSetField(eth_dst=eth_src),
							parser.OFPActionSetField(ipv4_dst=ipv4_src),
							parser.OFPActionSetField(tcp_dst=tcp_src),
							parser.OFPActionOutput(in_port)]
		elif pkt_udp:
			# print "@@@ Install UDP Flow Entry @@@"
			udp_src = pkt_udp.src_port
			udp_dst = pkt_udp.dst_port

			match = parser.OFPMatch(in_port=in_port,
									eth_type=ether.ETH_TYPE_IP,
									ip_proto=inet.IPPROTO_UDP,
									ipv4_src=ipv4_src,
									ipv4_dst=ipv4_dst,
									udp_src=udp_src,
									udp_dst=udp_dst)

			actions = [parser.OFPActionSetField(eth_dst=IP_TO_MAC_TABLE[target_ip]),
					   parser.OFPActionSetField(ipv4_src=self.nat_public_ip),
					   parser.OFPActionSetField(udp_src=nat_port),
					   parser.OFPActionOutput(out_port)]

			match_back = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
										 ip_proto=inet.IPPROTO_UDP,
										 ipv4_src=ipv4_dst,
										 ipv4_dst=self.nat_public_ip,
										 udp_src=udp_dst,
										 udp_dst=nat_port)

			actions_back = [parser.OFPActionSetField(eth_dst=eth_src),
							parser.OFPActionSetField(ipv4_dst=ipv4_src),
							parser.OFPActionSetField(udp_dst=udp_src),
							parser.OFPActionOutput(in_port)]
		else:
			pass

		self.add_flow(datapath, match=match, actions=actions,
					  idle_timeout=self.IDLE_TIME, priority=10)
		self.add_flow(datapath, match=match_back, actions=actions_back,
					  idle_timeout=self.IDLE_TIME, priority=10)

		d = None
		if buffer_id == ofproto.OFP_NO_BUFFER:
			d = data

		out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
								  in_port=in_port, actions=actions, data=d)
		datapath.send_msg(out)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		# ofproto = datapath.ofproto
		# parser = datapath.ofproto_parser
		in_port = msg.match['in_port']
		pkt = packet.Packet(msg.data)

		pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
		pkt_arp = pkt.get_protocol(arp.arp)
		# pkt_icmp = pkt.get_protocol(icmp.icmp)
		pkt_ip = pkt.get_protocol(ipv4.ipv4)
		pkt_tcp = pkt.get_protocol(tcp.tcp)
		pkt_udp = pkt.get_protocol(udp.udp)

		if in_port == self.wan_port:
			# Packets from WAN port
			if pkt_arp:
				if pkt_arp.opcode == arp.ARP_REQUEST:
					arp_reply_pkt = self._arp_request_handler(pkt_arp)
					self._send_packet_to_port(datapath, in_port, arp_reply_pkt)
				elif pkt_arp.opcode == arp.ARP_REPLY:
					self._arp_reply_handler(pkt_arp)
			else:
				# DNAT Part
				pass
		else:
			# Packets from LAN port
			if pkt_ip:

				if (self._in_private_subnetwork(pkt_ip.dst) and pkt_ip.dst != str(self.private_subnetwork[1])):
					# print "Private network %s" %pkt_ip.dst
					# These packets are private network
					# l2switch will handle it
					return

				ip_dst = pkt_ip.dst
				if (self._is_public(ip_dst) and
					not self._in_nat_public_ip_subnetwork(ip_dst)):
					# If the ip_dst of packet is public ip and on Internet
					target_ip = self.gateway
				elif self._in_nat_public_ip_subnetwork(ip_dst):
					# If the ip_dst of packet is public ip and on subnetwork of NAT
					target_ip = ip_dst
				else:
					return

				# Sending ARP request to Gateway
				arp_req_pkt = nat_helper.broadcast_arp_request(src_mac=self.MAC_ON_WAN,
															   src_ip=self.nat_public_ip,
															   target_ip=target_ip)
				self._send_packet_to_port(datapath, self.wan_port, arp_req_pkt)

				if pkt_tcp:
					if target_ip in IP_TO_MAC_TABLE:
						self._private_to_public(datapath=datapath,
												buffer_id=msg.buffer_id,
												data=msg.data,
												in_port=in_port,
												out_port=self.wan_port,
												pkt_ethernet=pkt_ethernet,
												pkt_ip=pkt_ip,
												pkt_tcp=pkt_tcp)
				elif pkt_udp:
					if target_ip in IP_TO_MAC_TABLE:
						self._private_to_public(datapath=datapath,
												buffer_id=msg.buffer_id,
												data=msg.data,
												in_port=in_port,
												out_port=self.wan_port,
												pkt_ethernet=pkt_ethernet,
												pkt_ip=pkt_ip,
												pkt_udp=pkt_udp)
			elif pkt_arp:
				if pkt_arp.opcode == arp.ARP_REQUEST:
					arp_reply_pkt = self._arp_request_handler(pkt_arp)
					self._send_packet_to_port(datapath, in_port, arp_reply_pkt)
				elif pkt_arp.opcode == arp.ARP_REPLY:
					pass