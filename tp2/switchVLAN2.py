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

    def vlan_members(self, dpid, in_port, src_vlan):

        access_ports = []
        trunk_ports = []

        if src_vlan == "NULL":
            return access_ports, trunk_ports
        # No switch, procura que VLANS estão associadas a cada porta.
        for item in port_vlan[dpid]:
            vlans = port_vlan[dpid][item]
            # Se houver uma vlan que queremos, e não seja a de entrada, guardamos.
            # Distinguimos se é access ou trunk por causa das ações que é necessário fazer. 
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
        
        if eth.ethertype == ether_types.ETH_TYPE_8021Q:  # Verificar se tem VLAN
            vlan_header_present = True
            src_vlan = vlan_header[0].vid
        elif dpid not in port_vlan:
            vlan_header_present = 0
            in_port_type = "NORMAL SWITCH "  # NORMAL NON-VLAN L2 SWITCH
            src_vlan = None
# Ver o que está antes do or, talvez apagar
        elif in_port in trunk[dpid]:   # Vem de trunk e não tem VLAN, estranho
            print("Não devia aparecer: Vem de trunk e sem VLAN")
            print(in_port)
            print(dpid)
            vlan_header_present = False
            in_port_type = "NORMAL UNTAGGED"  # NATIVE VLAN PACKET
            src_vlan = None 
        else:
            vlan_header_present = False   # Vem de um host
            src_vlan = port_vlan[dpid][in_port][0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst = eth.dst
        src = eth.src

        # Guardar no dicionário porta de entrada
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        access_ports, trunk_ports = self.vlan_members(dpid, in_port, src_vlan)
        out_port_type = " "

        # Se o switch já sabe para que porta deve enviar, pelo MAC de destino
        if dst in self.mac_to_port[dpid]:  
            out_port_unknown = False
            out_port = self.mac_to_port[dpid][dst]
            if src_vlan != None:
                if out_port in access[dpid]:
                    out_port_type = "ACCESS"
                else:
                    out_port_type = "TRUNK"
        else:
            out_port_unknown = True
            # List of All Access Ports Which are Members of Same VLAN (to Flood the Traffic)
            out_port_access = access_ports
            # List of All Trunk  Ports Which are Members of Same VLAN (to Flood the Traffic)
            out_port_trunk = trunk_ports


#########################################  -----FLOW ENTRY ADDITION SEGMENT    ----###############################################
        # Se conhecermos porta de saída
        if out_port_unknown != True:
            # Se tem Header VLAN (veio de fora) e vai para porta de acesso
            if vlan_header_present and out_port_type == "ACCESS":
                match = parser.OFPMatch(
                    in_port=in_port, eth_dst=dst, vlan_vid=(0x1000 | src_vlan))
                actions = [parser.OFPActionPopVlan(), parser.OFPActionOutput(
                    out_port)]   
            # Se tem VLAN header e vai para fora, manter VLAN HEADER
            elif vlan_header_present and out_port_type == "TRUNK":
                match = parser.OFPMatch(
                    in_port=in_port, eth_dst=dst, vlan_vid=(0x1000 | src_vlan))
                actions = [parser.OFPActionOutput(out_port)]
            # Se vem de um host e vai para fora (meter VLAN Header)
            elif not vlan_header_present  and out_port_type == "TRUNK":
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                actions = [parser.OFPActionPushVlan(33024), parser.OFPActionSetField(
                    vlan_vid=(0x1000 | src_vlan)), parser.OFPActionOutput(out_port)]
            else:
                print("Não devia aparecer, é porta acess para porta access, só dos servidores do piso 0")
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                actions = [parser.OFPActionOutput(out_port)]

            # verify if we have a valid buffer_id, if avoid yes to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        else:  # Não sabemos porta de saída
            if vlan_header_present:  
                match = parser.OFPMatch(
                    in_port=in_port, eth_dst=dst, vlan_vid=(0x1000 | src_vlan))
                actions = self.getActionsArrayTrunk(
                    out_port_access, out_port_trunk, parser)
            # IF UNTAGGED  BUT GENERATED FROM VLAN ASSOCIATED PORT
            # Vem de um host, sabemos qual a vlan de origem
            elif not vlan_header_present and src_vlan != "NULL":
                
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                actions = self.getActionsArrayAccess(
                    out_port_access, out_port_trunk, src_vlan, parser, dpid, in_port)
            elif in_port_type == "NORMAL UNTAGGED":
                print("Acho que não devia aparecer")
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                actions = self.getActionsNormalUntagged(dpid, in_port, parser)
            else:
                print("SWITCH normal")
                # FOR NORMAL NON-VLAN L2 SWITCH
                actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                print("Não devia aparecer isto!!!")

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
