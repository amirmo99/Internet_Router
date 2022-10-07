/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> IP_PROT_UDP = 0x11;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<8> key_t;

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

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header reqHdr_t {
    key_t key;
}

header resHdr_t {
    key_t key;
    bit<8> is_valid;
    bit<32> value;
}

struct metadata { }

struct headers { 
    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
    reqHdr_t reqHdr;
    resHdr_t resHdr;
}

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
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROT_UDP: parse_udp;
            default: accept ;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition check_request;
    }

    // State for checking reqHdr header
    state check_request {
        transition select(hdr.udp.dstPort) {
            1234: parse_request;
            default: check_response;
        }
    }

    // State for parsing resHdr header
    state check_response {
        transition select(hdr.udp.srcPort) {
            1234: parse_response;
            default: accept;
        }
    }

    state parse_request {
        packet.extract(hdr.reqHdr);
        transition accept;
    }

    state parse_response {
        packet.extract(hdr.resHdr);
        transition accept;
    }

}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    // We use two registers, one for storing the cached values, and another one for
    // tracking the available keys in the cache.
    register<bit<32>>(256) myCahce;
    register<bit<1>>(256) myCahce_check;

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    // This function responds a request message with value=val
    // Sets the resHdr, removes the reqHdr, and then sends the packet back to the client
    // It also sends back packets to the port they came from
    action reply_value(bit<32> val) {
        // Specifying the output port
        standard_metadata.egress_spec = standard_metadata.ingress_port;

        // Modifying resHdr
        hdr.resHdr.setValid();
        hdr.resHdr.key = hdr.reqHdr.key;
        hdr.resHdr.value = val;
        hdr.resHdr.is_valid = 1;

        // Disabling resReq
        hdr.reqHdr.setInvalid();

        // Modifying ethernet header
        macAddr_t tmpDstMac = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmpDstMac;

        // Modifying IPv4 header
        ip4Addr_t tmpDstIp = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = tmpDstIp;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 5;

        // Modifying UDP header
        bit<16> tmpDstPort = hdr.udp.dstPort;
        hdr.udp.dstPort = hdr.udp.srcPort;
        hdr.udp.srcPort = tmpDstPort;
        hdr.udp.checksum = 0;
        hdr.udp.length_ = hdr.udp.length_ + 5;
    }

    // Normal IPv4 forwarding table
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    // The table that holds key-values provided by controller 
    table cache_table {
        key = {
            hdr.reqHdr.key: exact;
        }
        actions = {
            reply_value;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    apply {
        // Check for a valid IPv4 packet
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
            
            // if the is a request we try to find the value associated with the key
            if (hdr.reqHdr.isValid()) {
                bit<1> check;

                // Look for the key in the registers
                myCahce_check.read(check, (bit<32>) hdr.reqHdr.key);
                if (check == 1) {
                    bit<32> val;
                    myCahce.read(val, (bit<32>) hdr.reqHdr.key);
                    reply_value(val);
                    return;
                }

                // Look for the key in the cache table maintained by controller
                if (cache_table.apply().hit) {
                    return;
                }
            } 
            
            // Caching values coming from server!
            // We only cache the values that actually exist in the server. NotFound values won't be cached!
            if (hdr.resHdr.isValid() && hdr.resHdr.is_valid == 1) { 
                myCahce.write((bit<32>)hdr.resHdr.key, hdr.resHdr.value);
                myCahce_check.write((bit<32>)hdr.resHdr.key, 1);
            }

            // Forward the IPv4 packet as normal
            ipv4_lpm.apply();
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
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

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.reqHdr);
        packet.emit(hdr.resHdr);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
