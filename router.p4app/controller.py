from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP, ICMP
from async_sniff import sniff
from headers import CPUMetadata, PWOSPF
import time
from ospf_helper import *

from consts import *


class RouterController(Thread):
    def __init__(self, router, routerID, areaID, start_wait=0.3):
        super(RouterController, self).__init__()
        self.router = router
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.iface = router.intfs[1].name
        self.switchIPs = [self.router.intfs[i].ip for i in range(1, len(self.router.intfs))]
        self.port_for_mac = {}
        self.stop_event = Event()
        self.ospfHelper = OSPFHelper(self, routerID, areaID)
        
        self.populateTables()
        
    def populateTables(self):
        # Local Table
        for ip in self.switchIPs:
            self.router.insertTableEntry(table_name='MyIngress.local_table',
                    match_fields={'hdr.ipv4.dstAddr': [ip]},
                    action_name='NoAction')
        self.router.insertTableEntry(table_name='MyIngress.local_table',
                match_fields={'hdr.ipv4.dstAddr': [IP_PROTO_PWOSPF]},
                action_name='NoAction')
        # Egress Mac Table
        for port, intf in self.router.intfs.items():
            if intf.mac and port >= 2:
                self.router.insertTableEntry(table_name='MyEgress.ports_mac_table',
                    match_fields={'standard_metadata.egress_port': [port]},
                    action_name='MyEgress.set_smac',
                    action_params={'mac': intf.mac})
        
        # Configuring ALLSPFRouter IP in the data plane
        self.router.insertTableEntry(table_name='MyIngress.routing_table',
                    match_fields={'hdr.ipv4.dstAddr': [ALLSPFRouters, 32]},
                    action_name='MyIngress.hello_broadcast',
                    action_params={'ipv4': [ALLSPFRouters]})
        
        # Setting up a multicast group for all ports except CPU
        self.router.addMulticastGroup(mgid=1, ports=range(2, len(self.router.intfs)+1))
        
        self.router.insertTableEntry(table_name='MyIngress.arp_table',
                    match_fields={'meta.routing.nhop_ipv4': [ALLSPFRouters]},
                    action_name='MyIngress.set_mgid',
                    action_params={'mgid': 1})
        self.router.insertTableEntry(table_name='MyIngress.fwd_l2',
            match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
            action_name='MyIngress.set_mgid',
            action_params={'mgid': 1})
        
    
    def addMacAddr(self, mac, port):
        # Don't re-add the mac-port mapping if we already have it:
        if mac in self.port_for_mac: return

        self.router.insertTableEntry(table_name='MyIngress.fwd_l2',
                match_fields={'hdr.ethernet.dstAddr': [mac]},
                action_name='MyIngress.set_egr',
                action_params={'port': port})
        self.port_for_mac[mac] = port

    def handleArpRequest(self, pkt):
        if pkt[ARP].pdst in self.switchIPs:
            tmp = pkt[ARP].pdst
            pkt[ARP].pdst = pkt[ARP].psrc
            pkt[ARP].psrc = tmp
            
            pkt[ARP].hwdst = pkt[ARP].hwsrc
            pkt[ARP].hwsrc = self.router.intfs[pkt[CPUMetadata].srcPort].mac       
            
            pkt[ARP].op = ARP_OP_REPLY
            
            self.swapEther(pkt)
            
        self.send(pkt)
    
    def swapEther(self, pkt):
        pkt[Ether].dst = pkt[Ether].src
        pkt[Ether].src = self.router.intfs[pkt[CPUMetadata].srcPort].mac
    
    def swapIP(self, pkt):
        tmp = pkt[IP].dst
        pkt[IP].dst = pkt[IP].src
        pkt[IP].src = tmp
    
    def handleICMP(self, pkt):
        if pkt[ICMP].type == ICMP_TYPE_REQUEST:
            if pkt[IP].dst in self.switchIPs:
                pkt[ICMP].type = ICMP_TYPE_REPLY
                self.swapIP(pkt)
                self.swapEther(pkt)
                self.send(pkt)
                

    def handlePkt(self, pkt):
        pkt.show2()
        assert CPUMetadata in pkt, "Should only receive packets from switch with special header"

        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1: return

        # Handling ARP packets
        if ARP in pkt:
            self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
            self.ospfHelper.addNeighbor(pkt[ARP].psrc, pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
            
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
        # Handle IP packets
        elif IP in pkt:
            if ICMP in pkt:
                self.handleICMP(pkt)
            if PWOSPF in pkt:
                self.ospfHelper.handlePacket(pkt)
        else:
            print("Not an IP packet! Dropping...")

    def send(self, *args, **override_kwargs):
        pkt = args[0]
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(*args, **kwargs)

    def run(self):
        sniff(iface=self.iface, prn=self.handlePkt, stop_event=self.stop_event)

    def start(self, *args, **kwargs):
        super(RouterController, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(RouterController, self).join(*args, **kwargs)
