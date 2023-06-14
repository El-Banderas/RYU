
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_TCP  = 0x06;
const bit<8> TYPE_UDP  = 0x11;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> port_t;

header ethernet_t {
	macAddr_t dstAddr;
	macAddr_t srcAddr;
	bit<16>   etherType;
}

header ipv4_t {
	bit<4>    version;
	bit<4>    ihl;
	bit<8>    diffserv;
	bit<16>   totalLen;
	bit<16>   identification;
	bit<3>    flags;
	bit<13>   fragOffset;
	bit<8>    ttl;
	bit<8>    protocol;
	bit<16>   hdrChecksum;
	ip4Addr_t srcAddr;
	ip4Addr_t dstAddr;
}

header tcp_t {
	port_t  srcPort;
	port_t  dstPort;
	bit<32> seqNo;
	bit<32> ackNo;
	bit<4>  dataOffset; // how long the TCP header is
	bit<3>  res;
	bit<3>  ecn;        // Explicit congestion notification
	bit<6>  ctrl;       // URG,ACK,PSH,RST,SYN,FIN
	bit<16> window;
	bit<16> checksum;
	bit<16> urgentPtr;
}

header udp_t {
	port_t  srcPort;
	port_t  dstPort;
	bit<16> length;
	bit<16> csum;
}


struct metadata {
	ip4Addr_t next_hop_ipv4;
	port_t    src_port_to_add;
	port_t    src_port_message;
	bool      is_tcp;
	bit<16>   tcp_length;
}

struct headers {
	ethernet_t ethernet;
	ipv4_t     ipv4;
	tcp_t      tcp;
	udp_t      udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
				out headers hdr,
				inout metadata meta,
				inout standard_metadata_t standard_metadata) {
	state start {
		transition parse_ethernet;
	}

	state parse_ethernet {
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.etherType) {
			TYPE_IPV4:  parse_ipv4;
			default: accept;
		}
	}
	state parse_ipv4 {
		packet.extract(hdr.ipv4);
		meta.tcp_length = hdr.ipv4.totalLen - 20;
		transition select(hdr.ipv4.protocol) {
			TYPE_TCP: parse_tcp;
			TYPE_UDP: parse_udp;
		}
	}

	state parse_tcp {
		packet.extract(hdr.tcp);
		meta.is_tcp = true;
		meta.src_port_message = hdr.tcp.dstPort;
		transition accept;
	}

	state parse_udp {
		packet.extract(hdr.udp);
		meta.is_tcp = false;
		meta.src_port_message = hdr.udp.dstPort;
		transition accept;
	}
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
	apply { /* do nothing */  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
				  inout metadata meta,
				  inout standard_metadata_t standard_metadata) {
	action drop() {
		mark_to_drop(standard_metadata);
	}
	
	// NoAction is defined in v1model - does nothing
	
	
	// NAT...

	action snat_translate(ip4Addr_t nat_src, port_t nat_port) {
		hdr.ipv4.srcAddr = nat_src;
		if (meta.is_tcp) {
			hdr.tcp.srcPort =  hdr.tcp.srcPort + nat_port;
		} else {
			hdr.udp.srcPort =  hdr.udp.srcPort + nat_port;
		}
	}
	
	table snat {
		key = {
			hdr.ipv4.srcAddr : exact;
		}
		actions = {
			snat_translate;
			NoAction;
			drop;
		}
		default_action = NoAction();
	}

	action dnat_translate(ip4Addr_t nat_dst) {
		hdr.ipv4.dstAddr = nat_dst;
		if (meta.is_tcp) {
			hdr.tcp.dstPort = hdr.tcp.dstPort - meta.src_port_to_add;
		} else {
			hdr.udp.dstPort = hdr.udp.dstPort - meta.src_port_to_add;
		}
	}
	
	table dnat {
		key = { 
			hdr.ipv4.srcAddr : exact; 
			meta.src_port_to_add : exact;
		}
		actions = {
			dnat_translate;
			NoAction;
			drop;
		}
		default_action = NoAction();
	}
	
	
	/* Normal routing stuff... */

	// Find next hop
	action ipv4_fwd(ip4Addr_t nxt_hop, egressSpec_t port) {
		meta.next_hop_ipv4 = nxt_hop;
		standard_metadata.egress_spec = port;
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
	}
	
	table ipv4_lpm {
		key = { hdr.ipv4.dstAddr : lpm; }
		actions = {
			ipv4_fwd;
			drop;
			NoAction;
		}
		default_action = drop; // NoAction is defined in v1model - does nothing
	}

	// Alterar src MAC
	action rewrite_src_mac(macAddr_t src_mac) {
		hdr.ethernet.srcAddr = src_mac;
	}

	table src_mac {
		key = { standard_metadata.egress_spec : exact; }
		actions = {
			rewrite_src_mac;
			drop;
		}
		default_action = drop;
	}

	// Alterar MAC destino    
	action rewrite_dst_mac(macAddr_t dst_mac) {
		hdr.ethernet.dstAddr = dst_mac;
	}

	// Vai buscar o IP guardado no meta (do utilizador)
	table dst_mac {
		key = { meta.next_hop_ipv4 : exact; }
		actions = {
			rewrite_dst_mac;
			drop;
		}
		default_action = drop;
	}


	apply {
		if (hdr.ipv4.isValid()) {
			if (meta.src_port_message > 6000 && meta.src_port_message < 7000){
				meta.src_port_to_add = 1000;
			}
			if (meta.src_port_message > 7000 && meta.src_port_message < 8000){
				meta.src_port_to_add = 2000;
			}
			if (meta.src_port_message > 8000 && meta.src_port_message < 9000){
				meta.src_port_to_add = 3000;
			}

			// NAT first
			snat.apply();
			dnat.apply();

			// Then routing
			ipv4_lpm.apply();
			src_mac.apply();
			dst_mac.apply();
		}

		// TODO: put this in MyComputeChecksum
		if (!meta.is_tcp){
			hdr.udp.csum = 0;
		}
	}
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
				 inout metadata meta,
				 inout standard_metadata_t standard_metadata) {
	apply { /* do nothing */ }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
	/* this recalculates the checksum */
	apply {
		update_checksum(
			hdr.ipv4.isValid(),
					{
					hdr.ipv4.version,
					hdr.ipv4.ihl,
					hdr.ipv4.diffserv,
					hdr.ipv4.totalLen,
					hdr.ipv4.identification,
					hdr.ipv4.flags,
					hdr.ipv4.fragOffset,
					hdr.ipv4.ttl,
					hdr.ipv4.protocol,
					hdr.ipv4.srcAddr,
					hdr.ipv4.dstAddr
					},
			hdr.ipv4.hdrChecksum,
			HashAlgorithm.csum16
		);

		update_checksum_with_payload(
			hdr.tcp.isValid(),
					{
					hdr.ipv4.srcAddr,
					hdr.ipv4.dstAddr,
					8w0,
					hdr.ipv4.protocol,
					meta.tcp_length,
					hdr.tcp.srcPort,
					hdr.tcp.dstPort,
					hdr.tcp.seqNo,
					hdr.tcp.ackNo,
					hdr.tcp.dataOffset,
					hdr.tcp.res,
					hdr.tcp.ecn,
					hdr.tcp.ctrl,
					hdr.tcp.window,
					hdr.tcp.urgentPtr,
					},
			hdr.tcp.checksum,
			HashAlgorithm.csum16
		);
	}
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
	apply {
		packet.emit(hdr.ethernet);
		packet.emit(hdr.ipv4);
		packet.emit(hdr.tcp);
		packet.emit(hdr.udp);
	}
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
