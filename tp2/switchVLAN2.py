# IMPLEMENTATION OF IEEE 802.1Q VLAN TAGGING AND UNTAGGING
# DESIRED VLAN CONFIGURATION IS KNOWN PRIORI AND MUST BE ADDED TO THE GLOBAL VARIABLES

# Name: VARUN NAIR
# STUDENT ID: 4504550
# DELFT UNIVERSITY OF TECHNOLOGY , Dept. of Electrical Engineering


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import vlan
from ryu.lib.packet import ether_types

# GLOBAL VARIABLES
port_vlan = {3: {1: [10, 20, 30], 2: [30], 3: [10], 4: [20]}, 2: {1: [10, 20, 30], 2: [10, 20, 30], 3: [30], 4: [10], 5: [20]}, 1: {1: [10], 2: [10, 20, 30], 3: [30], 4: [10], 5: [20]}

             }  # port_vlan[a][b]=c => 'a'= dpid, 'b'= port number,'c'= VLAN ID

# access[a]=[B] => 'a' = dpid ,'[B]'=List of ports configured as Access Ports
access = {3: [2, 3, 4], 2: [3, 4, 5], 1: [1, 3, 4, 5]}

# trunk[a]=[B] => 'a' = dpid ,'[B]'=List of ports configured as Trunk Ports
trunk = {3: [1], 2: [1, 2], 1: [2]}


class VlanSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(VlanSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

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
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
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

    # Rita, depois põe a retornar as portas de acesso e trunk, em vez de guardar no self
    def vlan_members(self, dpid, in_port, src_vlan):

        access_ports = []
        trunk_ports = []

        if src_vlan == "NULL":
            return access_ports, trunk_ports

        # E acho que dá para juntar estes dois fors, aqui podes logo verificar se é de acesso ou trunk
        for item in port_vlan[dpid]:
            vlans = port_vlan[dpid][item]
            if src_vlan in vlans and item != in_port:
                if item in access[dpid]:
                    access_ports.append(item)
                else:
                    trunk_ports.append(item)
        return access_ports, trunk_ports

# ---------------------------------------------------------------#

    def getActionsArrayTrunk(self, out_port_access, out_port_trunk, parser):
        actions = []

        for port in out_port_trunk:
            actions.append(parser.OFPActionOutput(port))

        actions.append(parser.OFPActionPopVlan())

        for port in out_port_access:
            actions.append(parser.OFPActionOutput(port))

        return actions

    def getActionsArrayAccess(self, out_port_access, out_port_trunk, src_vlan, parser, dpid, in_port):
        print("Info, out port access: ", out_port_access)
        print("out port trunk: ", out_port_trunk)
        print("src vlan: ", src_vlan)
        print("dpid: ", dpid)
        print("in port ", in_port)
        actions = []

        for port in out_port_access:
            actions.append(parser.OFPActionOutput(port))

        actions.append(parser.OFPActionPushVlan(33024))
        actions.append(parser.OFPActionSetField(vlan_vid=(0x1000 | src_vlan)))

        for port in out_port_trunk:
            actions.append(parser.OFPActionOutput(port))

        return actions


# ---------------------------------------------------------------#

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
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

        # SWITCH ID
        dpid = datapath.id
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        # If packet is tagged,then this will have non-null value
        vlan_header = pkt.get_protocols(vlan.vlan)
        # Aqui também há casos que acho que se pode tirar, eu marquei-os
        if eth.ethertype == ether_types.ETH_TYPE_8021Q:  # Checking for VLAN Tagged Packet
            vlan_header_present = 1
            src_vlan = vlan_header[0].vid
        elif in_port in trunk[dpid]:
            vlan_header_present = 0
            src_vlan = "NULL" # a porta de entrada é uma porta trunk e não está associada a uma VLAN específica
        else:
            vlan_header_present = 0
            # STORE VLAN ASSOCIATION FOR THE IN PORT
            src_vlan = port_vlan[dpid][in_port][0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst = eth.dst
        src = eth.src

        # CREATE NEW DICTIONARY ENTRY IF IT DOES NOT EXIST
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        # Determine which ports are members of in_port's VLAN
        # Rita, aqui passa a devolver o par das portas de acesso e trunk
        access_ports, trunk_ports = self.vlan_members(dpid, in_port, src_vlan)
        out_port_type = " "

        if dst in self.mac_to_port[dpid]:  # MAC ADDRESS TABLE CREATION
            out_port_unknown = 0
            out_port = self.mac_to_port[dpid][dst]
            if src_vlan != "NULL":
                if out_port in access[dpid]:
                    out_port_type = "ACCESS"
                else:
                    out_port_type = "TRUNK"
        else:
            out_port_unknown = 1
            # List of All Access Ports Which are Members of Same VLAN (to Flood the Traffic)
            out_port_access = access_ports
            # List of All Trunk  Ports Which are Members of Same VLAN (to Flood the Traffic)
            out_port_trunk = trunk_ports


#########################################  -----FLOW ENTRY ADDITION SEGMENT    ----###############################################
# APAGAR#
        '''
        # Caso destino esteja ligado ao mesmo switch/dpid, out_port = porta do destino, senão fazer flood
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

		# self.logger.info("packet_in | dpid=%s src=%s dst=%s in_port=%s out_port=%s", dpid, src, dst, in_port, out_port)
		# print("packet_in | mac_to_port=", self.mac_to_port)

        actions = [parser.OFPActionOutput(out_port)]

		# install a flow to avoid packet_in next time
        # Sabendo o in_port e out_port (not flood), adicionar flow ao switch?
        if out_port != ofproto.OFPP_FLOOD:
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
        return
        '''
# Apagar#
        # Aqui ver que casos dá para tirar, tipo switchs normais e assim
        # IF OUT PORT IS KNOWN
        if out_port_unknown != 1:
            # If VLAN Tagged and needs to be sent out through ACCESS port
            if vlan_header_present and out_port_type == "ACCESS":
                print("Trunk->Access")
                match = parser.OFPMatch(
                    in_port=in_port, eth_dst=dst, vlan_vid=(0x1000 | src_vlan))
                actions = [parser.OFPActionPopVlan(), parser.OFPActionOutput(
                    out_port)]   # STRIP VLAN TAG and SEND TO OUTPUT PORT
            elif vlan_header_present and out_port_type == "TRUNK":
                print("Trunk->Trunk")
                match = parser.OFPMatch(
                    in_port=in_port, eth_dst=dst, vlan_vid=(0x1000 | src_vlan))
                # SEND THROUGH TRUNK PORT AS IS
                actions = [parser.OFPActionOutput(out_port)]
            elif vlan_header_present != 1 and out_port_type == "TRUNK":
                print("Access->Trunk")
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                actions = [parser.OFPActionPushVlan(33024), parser.OFPActionSetField(
                    vlan_vid=(0x1000 | src_vlan)), parser.OFPActionOutput(out_port)]
            else:
                print("Access->Access")
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                actions = [parser.OFPActionOutput(out_port)]

            # verify if we have a valid buffer_id, if avoid yes to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        else:  # FOR FLOODING ACTIONS
            if vlan_header_present:  # IF TAGGED
                print("Trunk->Floood")
                match = parser.OFPMatch(
                    in_port=in_port, eth_dst=dst, vlan_vid=(0x1000 | src_vlan))
                actions = self.getActionsArrayTrunk(
                    out_port_access, out_port_trunk, parser)
            # IF UNTAGGED  BUT GENERATED FROM VLAN ASSOCIATED PORT
            elif vlan_header_present == 0 and src_vlan != "NULL":
                print("Access->Floood")
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                actions = self.getActionsArrayAccess(
                    out_port_access, out_port_trunk, src_vlan, parser, dpid, in_port)

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
