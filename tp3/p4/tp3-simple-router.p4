/* -*- P4_16 -*- */
/**
* The following includes 
* should come form /usr/share/p4c/p4include/
* The files :
 * ~/RDS-tut/p4/core.p4
 * ~/RDS-tut/p4/v1model.p4
* are here if you need/want to consult them
*/
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_TCP  = 0x06;
const bit<8> TYPE_UDP  = 0x11;
const bit<8> TYPE_ICMP  = 0x01;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

/* simple typedef to ease your task */

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/**
* Here we define the headers of the protocols
* that we want to work with.
* A header has many fields you need to know all of them
* and their sizes.
* All the headers that you will need are already declared.
*/

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
    bit<16> srcPort;
    bit<16> dstPort;
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
	bit<16> srcPort;
	bit<16> dstPort;
	bit<16> length;
	bit<16> csum;
}

/**
* You can use this structure to pass 
* information between blocks/pipelines.
* This is user-defined. You can declare your own
* variables inside this structure.
*/
struct metadata {
    ip4Addr_t   next_hop_ipv4;
}
/* all the headers previously defined */
struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
	udp_t      udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    /**
     * a parser always begins in the start state
     * a state can invoke other state with two methods
     * transition <next-state>
     * transition select(<expression>) -> works like a switch case
     */
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
        packet.extract(hdr.ipv4); // extract function populates the ipv4 header

		transition select(hdr.ipv4.protocol) {
			TYPE_TCP: parse_tcp;
			TYPE_UDP: parse_udp;
			TYPE_ICMP: parse_icmp;
		}
    }
    state parse_icmp {
		transition accept;
	}
    state parse_tcp {
		packet.extract(hdr.tcp);
		transition accept;
	}

	state parse_udp {
		packet.extract(hdr.udp);
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
    
    /**
    * this is your main pipeline
    * where we define the actions and tables
    */

   // Rewrite src add
    action snat_translate(ip4Addr_t nat_ip_src, bit<16> src_port) {
        hdr.ipv4.srcAddr  = nat_ip_src;
        hdr.tcp.srcPort  = src_port;
    }
    
    table snat {
        key = { hdr.ipv4.srcAddr  : exact; hdr.ipv4.dstAddr  : exact; hdr.tcp.srcPort : exact;hdr.tcp.dstPort : exact;}
        actions = {
            snat_translate;
            drop;
            NoAction;
        }
        default_action = NoAction(); // NoAction is defined in v1model - does nothing
        }
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
        default_action = NoAction(); // NoAction is defined in v1model - does nothing
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
        /**
        * The conditions and order in which the software 
        * switch must apply the tables. 
        */
        if (hdr.ipv4.isValid()) {
            snat.apply();
            ipv4_lpm.apply();
            src_mac.apply();
            dst_mac.apply();
            //src_rw.apply();
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
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        /**
        * add the extracted headers to the packet 
        * packet.emit(hdr.ethernet);
        */
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
/*
 * Architecture.
 *
 * M must be a struct.
 *
 * H must be a struct where every one if its members is of type
 * header, header stack, or header_union.
 *
 * package V1Switch<H, M>(Parser<H, M> p,
 *                      VerifyChecksum<H, M> vr,
 *                      Ingress<H, M> ig,
 *                      Egress<H, M> eg,
 *                      ComputeChecksum<H, M> ck,
 *                      Deparser<H> dep
 *                      );
 * you can define the blocks of your sowtware switch in the following way:
 */

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
