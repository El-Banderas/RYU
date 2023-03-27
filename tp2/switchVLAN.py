# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#	 http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class SimpleSwitch13(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(SimpleSwitch13, self).__init__(*args, **kwargs)
		self.mac_to_port = {}													# Dicionário(s)	 device -> (mac_addr -> port)

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# install table-miss flow entry
		#
		# We specify NO BUFFER to max_len of the output action due to
		# OVS bug. At this moment, if we specify a lesser number, e.g.,
		# 128, OVS will send Packet-In with invalid buffer_id and
		# truncated packet data. In that case, we cannot output packets
		# correctly.  The bug has been fixed in OVS v2.1.0.
		match = parser.OFPMatch()										# Outro exemplo de FlowMode, quando não sabe o que fazer à mensagem, enviar ao controlador.
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,		# Também não deve guardar no buffer do equipamento.
										  ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)


	def add_flow(self, datapath, priority, match, actions, buffer_id=None):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
											 actions)]
		if buffer_id:				 											
			mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
									priority=priority, match=match,
									instructions=inst)
		else:
			mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
									match=match, instructions=inst)
		datapath.send_msg(mod)

	def vlans_by_port(dpid, in_port, src_vlan): 						#retirar src?
		acess_ports = []
		trunk_ports = []
		ports_of_pkt = [] #lista intermedia

		for port_in_switch in port_vlan[dpid]:
			vlans = port_vlan[dpid][port_in_switch]
			if src_vlan in vlans and port_in_switch != in_port:
				ports_of_pkt.append(port_in_switch)

		for port in ports_of_pkt:
			if port in acess_ports[dpid]:
				acess_ports=
		




	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)					# Definir handler de pacotes recebidos ( type of event this function is called for = ofp_event.EventOFPPacketIn) com o decorator 'set_ev_cls'
	def _packet_in_handler(self, ev):
		# If you hit this you might want to increase
		# the "miss_send_length" of your switch
		if ev.msg.msg_len < ev.msg.total_len:
			self.logger.debug("packet truncated: only %s of %s bytes",
							  ev.msg.msg_len, ev.msg.total_len)
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']

		pkt = packet.Packet(msg.data)											# Reconstruir pacote apartir de msg.data
		eth = pkt.get_protocols(ethernet.ethernet)[0]							# "Ler" encapsulamento Ethernet

		vlan_header= pkt.get_protocols(vlan.vlan)


		if vlan_header is None:
			is_vlan =  False
			src_vlan = port_vlan[dpid][in_port][0] 								
		else: 
			is_vlan = True
			src_vlan = vlan_header[0].vid

		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
			# ignore lldp packet
			return
		
		dst = eth.dst															# "Ler" mac_addr_dst
		src = eth.src															# "Ler" mac_addr_src

		dpid = format(datapath.id, "d").zfill(16)								# int to string & pad 0 à esquerda
		self.mac_to_port.setdefault(dpid, {})									# Caso dpid não exista, criar dpid->{} primeiro para não dar erro

		# learn a mac address to avoid FLOOD next time.
		self.mac_to_port[dpid][src] = in_port									# Como diz o comentário, adicionar entrada dpid -> ( mac_addr_src -> in_port )

																				# Dois exemplos de  FLOWMods.
		if dst in self.mac_to_port[dpid]:										# Caso destino esteja ligado ao mesmo switch/dpid, out_port = porta do destino, senão fazer flood
			out_port = self.mac_to_port[dpid][dst]
		else:
			out_port = ofproto.OFPP_FLOOD
			
		#self.logger.info("packet_in | dpid=%s src=%s dst=%s in_port=%s out_port=%s", dpid, src, dst, in_port, out_port)
		#print("packet_in | mac_to_port=", self.mac_to_port)

		actions = [parser.OFPActionOutput(out_port)]

		# install a flow to avoid packet_in next time
		if out_port != ofproto.OFPP_FLOOD:										# Sabendo o in_port e out_port (not flood), adicionar flow ao switch?
			match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
			# verify if we have a valid buffer_id, if yes avoid to send both
			# flow_mod & packet_out
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