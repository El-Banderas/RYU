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

from ryu.topology import event

import sys
import ruamel.yaml
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
		self.hosts = {}

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
		print(str(ev))

	
	@set_ev_cls(event.EventHostAdd)
	def _host_add_handler(self, ev):

		dpid = ev.host.port.dpid
		port_no = ev.host.port.port_no
		mac = ev.host.mac

		self.hosts.setdefault(dpid, {})
		self.hosts[dpid][port_no] = {"mac":mac, "status":1}
		print(self.hosts)

	@set_ev_cls(event.EventPortModify)
	def _port_modify_handler(self, ev):
		print("Evento")
		print(ev)
		dpid = ev.port.dpid
		port_no = ev.port.port_no
		status = 1 if ev.port.is_live() else 0
		# Se o estado anterior for igual ao atual, não modifica nada
		if (self.hosts[dpid][port_no]["status"] == status):
			return 
		self.hosts[dpid][port_no]["status"] = status
		print(self.hosts)
		self.output_dict()


	def output_dict(self):
		yaml = ruamel.yaml.YAML()  # defaults to round-trip
		print("YAML")
		dic_final = {}
		current_entryes_number = 0
		for switch_name, switch_devices in self.hosts.items():
			dic_final[switch_name] = clean_switch(switch_devices)
		print("Final")
		print(dic_final)

		now = datetime.now()

		current_time = now.strftime("%H:%M:%S")
		f = open(current_time + ".txt", "a")
		yaml.dump(dic_final, f)
		yaml.dump(dic_final, sys.stdout)
		last_entryes_number = current_entryes_number
		f.close()
