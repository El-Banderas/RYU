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
        # inicializa um dicionário para armazenar as associações entre endereços MAC e portas
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        #Quando o controlador se conecta a um switch, o switch envia uma mensagem OFPSwitchFeatures
        #com informações sobre as suas capacidades. Esta função é chamada quando essa mensagem é recebida.
        datapath = ev.msg.datapath #path que representa o switch 
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser # parser para criar mensagens OpenFlow 

        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.

        # install table-miss flow entry
        match = parser.OFPMatch() #default match para todos os pacotes
        #ação para fazer o forward dos pacotes sem entradas para o controller
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        #
        self.add_flow(datapath, 0, match, actions)

    #Esta funçao adiciona uma entrada de fluxo ao switch. Cria e envia uma mensagem OFPFlowMod para o switch, 
    # instruindo-o a adicionar uma entrada de fluxo com as especificações fornecidas.
    #Argumentos:
    #datapath   - objeto datapath que representa o switch
    #priority   - prioridade da entrada de fluxo
    #match      - condição de correspondência do fluxo (ex. endereço MAC de origem e destino)
    #actions    - lista de ações a serem executadas quando o fluxo corresponder (ex. encaminhar para uma porta)
    #buffer_id  - (opcional) ID do buffer temporário onde o pacote está armazenado; se fornecido,
    #o switch processa o pacote armazenado no buffer de acordo com a entrada de fluxo adicionada
        
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Cria a instrução com as ações fornecidas
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        
        # Cria a mensagem OFPFlowMod e a envia para o switch      
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    #esta funçao retorna uma lista de portas de acesso e trunk que pertencem a uma VLAN específica.
    # itera sobre o dicionário de associações de VLANs e adiciona as portas que pertencem
    #à VLAN especificada às listas de portas de acesso ou trunk.
    #Argumentos:
    #dpid      - ID do datapath (switch) no qual as portas estão localizadas
    #in_port   - número da porta de entrada 
    #src_vlan  - ID da VLAN para a qual se deseja obter as portas de acesso e tronco
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
                    # Adiciona o membro à lista de membros da VLAN
                    access_ports.append(item)
                else:
                    trunk_ports.append(item)
        return access_ports, trunk_ports

# ---------------------------------------------------------------#

    #esta função cria e retorna uma lista de ações a serem executadas em portas trunk e portas de acesso
    #Argumentos:
    #out_port_access: Lista de portas de acesso que fazem parte da mesma VLAN
    #out_port_trunk: Lista de portas trunk que fazem parte da mesma VLAN
    #parser: Objeto de parser do datapath do switch para criar ações
    def getActionsArrayTrunk(self, out_port_access, out_port_trunk, parser):
        actions = []

        for port in out_port_trunk:
            actions.append(parser.OFPActionOutput(port))

        # Adiciona ação de remover o cabeçalho VLAN
        actions.append(parser.OFPActionPopVlan())

         # Adiciona ação de saída para cada porta de acesso na lista out_port_access
        for port in out_port_access:
            actions.append(parser.OFPActionOutput(port))

        return actions

    #cria e retorna uma lista de ações para serem executadas em portas de acesso e portas trunk.
    #Argumentos:
    #out_port_access: Lista de portas de acesso que fazem parte da mesma VLAN
    #out_port_trunk: Lista de portas trunk que fazem parte da mesma VLAN
    #src_vlan (int): VLAN de origem
    #parser: Objeto de parser do datapath do switch para criar ações
    #dpid (int): ID do datapath do switch
    #in_port (int): Porta de entrada
    def getActionsArrayAccess(self, out_port_access, out_port_trunk, src_vlan, parser, dpid, in_port):
        
        actions = []

        #Adiciona ação de saída para cada porta de acesso na lista out_port_access
        for port in out_port_access:
            actions.append(parser.OFPActionOutput(port))

        #Adiciona ação de inserir cabeçalho VLAN.
        actions.append(parser.OFPActionPushVlan(33024))
        #Adiciona ação de definir o campo vlan_vid com a VLAN de origem.
        	# actions = [parser.OFPActionPushVlan(33024), parser.OFPActionSetField(
        	# 		vlan_vid=(0x1000 | src_vlan)), parser.OFPActionOutput(out_port)]
        actions.append(parser.OFPActionSetField(vlan_vid=(0x1000 | src_vlan)))

        #Adiciona ação de saída para cada porta tronco na lista out_port_trunk
        for port in out_port_trunk:
            actions.append(parser.OFPActionOutput(port))

        return actions


# ---------------------------------------------------------------#

    #esta função manipula eventos de pacotes recebidos pelo switch e gerencia o encaminhamento de pacotes e adição de fluxos
    #Argumentos:
    #ev: Evento de entrada do pacote
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        #se o tamanho da mensagem for menor que o tamanho total, pode ser necessário aumentar o "miss_send_length" do switch
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
        #se o pacote possuir uma tag VLAN, vlan_header terá um valor diferente de null
        vlan_header = pkt.get_protocols(vlan.vlan)

        #verificar se o pacote possui uma VLAN
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

        # Ignorar pacotes LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        # Guardar no dicionário a porta de entrada
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        access_ports, trunk_ports = self.vlan_members(dpid, in_port, src_vlan)
        out_port_type = " "

        # Se o switch já sabe para que porta deve enviar, com base no MAC de destino
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
            # Se vem de um host e vai para fora (adicionar VLAN Header)
            elif not vlan_header_present  and out_port_type == "TRUNK":
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                actions = [parser.OFPActionPushVlan(33024), parser.OFPActionSetField(
                    vlan_vid=(0x1000 | src_vlan)), parser.OFPActionOutput(out_port)]
            else:
                print("Não devia aparecer, é porta acess para porta access, só dos servidores do piso 0")
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                actions = [parser.OFPActionOutput(out_port)]

            #verificar se temos um buffer_id válido, caso contrário, enviar ambos flow_mod & packet_out
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
            #se não possui VLAN header, mas foi gerado a partir de uma porta associada à VLAN
            # Vem de um host, sabemos qual a vlan de origem
            elif not vlan_header_present and src_vlan != None:
                
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
