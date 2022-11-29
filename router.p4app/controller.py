from threading import Thread, Event, Lock
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP, ICMP
from async_sniff import sniff
from headers import CPUMetadata, PWOSPF
import time
from ospf_helper import *

from consts import *


class RouterController(Thread):
    def __init__(self, router, areaID, start_wait=0.3):
        super(RouterController, self).__init__()
        self.router = router
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.iface = router.intfs[1].name
        self.switchIPs = [self.router.intfs[i].ip for i in range(1, len(self.router.intfs))]
        self.port_for_mac = {}
        self.routing_entries = {}
        self.arp_entries = {}
        self.stop_event = Event()
        self.ospfHelper = OSPFHelper(self, areaID)
        
        self.arp_timeout = 10
        self.waitingList = []
        self.arpLock = Lock()
        
        self.populateTables()
        
        # Timer(5, self.timeoutTimer).start()
        
    def timeoutTimer(self):
        Timer(1, self.timeoutTimer).start()
        to_remove = []
        with self.arpLock:
            for item in self.waitingList:
                item[1] -= 1
                if item[1] < 0:
                    to_remove.append(item)
            for item in to_remove:
                self.waitingList.remove(item)
        for item in to_remove:
            self.unreachable(item[0])
    
    def unreachable(self, pkt):
        print('Host unreachable')
        
    def populateTables(self):
        # Local Table
        for ip in self.switchIPs:
            self.router.insertTableEntry(table_name='MyIngress.local_table',
                    match_fields={'hdr.ipv4.dstAddr': [ip]},
                    action_name='NoAction')
        # Egress Mac Table
        for port, intf in self.router.intfs.items():
            if intf.mac and port >= 2:
                self.router.insertTableEntry(table_name='MyEgress.ports_mac_table',
                    match_fields={'standard_metadata.egress_port': [port]},
                    action_name='MyEgress.set_smac',
                    action_params={'mac': intf.mac})
        
        # Arp entry for OSPF broadcast
        self.addArpEntry(ALLSPFRoutersIP, 'ff:ff:ff:ff:ff:ff')
        
        # Configuring ALLSPFRouter IP in the data plane
        # self.router.insertTableEntry(table_name='MyIngress.routing_table',
        #             match_fields={'hdr.ipv4.dstAddr': [ALLSPFRoutersIP, 32]},
        #             action_name='MyIngress.hello_broadcast',
        #             action_params={'ipv4': [ALLSPFRoutersIP]})
        
        # Setting up a multicast group for all ports except CPU
        # self.router.addMulticastGroup(mgid=1, ports=range(2, len(self.router.intfs)))
        
        # self.router.insertTableEntry(table_name='MyIngress.arp_table',
        #             match_fields={'meta.routing.nhop_ipv4': [ALLSPFRoutersIP]},
        #             action_name='MyIngress.set_mgid',
        #             action_params={'mgid': 1})
        # self.router.insertTableEntry(table_name='MyIngress.fwd_l2',
        #     match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
        #     action_name='MyIngress.set_mgid',
        #     action_params={'mgid': 1})
        
    
    def addMacAddr(self, mac, port):
        # Don't re-add the mac-port mapping if we already have it:
        if mac in self.port_for_mac: return

        self.router.insertTableEntry(table_name='MyIngress.fwd_l2',
                match_fields={'hdr.ethernet.dstAddr': [mac]},
                action_name='MyIngress.set_egr',
                action_params={'port': port})
        self.port_for_mac[mac] = port
        
    def addArpEntry(self, ip, mac):
        if ip in self.arp_entries:
            return
        
        self.router.insertTableEntry(table_name='MyIngress.arp_table',
                    match_fields={'meta.routing.nhop_ipv4': [ip]},
                    action_name='MyIngress.set_dmac',
                    action_params={'dmac': mac})
        self.arp_entries[ip] = mac
        
    def addRoutingEntry(self, subnet, prefixLen, port, nhop):
        if (subnet, prefixLen) in self.routing_entries:
            return
        
        entry = {'table_name':'MyIngress.routing_table', 'match_fields':{'hdr.ipv4.dstAddr': [subnet, prefixLen]},
                    'action_name':'MyIngress.set_nhop',
                    'action_params':{'port': [port], 'ipv4': [nhop]}}
        
        self.router.insertTableEntry(entry=entry)
        self.routing_entries[(subnet, prefixLen)] = (port, nhop, entry)
        
    def delAllRoutingEntries(self):
        self.routing_entries.clear()

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
    
    def handleArpReply(self, pkt): 
        if pkt[ARP].pdst in self.switchIPs:
            print('Arp reply received!')
            to_remove = []
            with self.arpLock:
                for item in self.waitingList:
                    if item[0][IP].dst in self.arp_entries:
                        to_remove.append(item)
                for item in to_remove:
                    self.waitingList.remove(item)
            for item in to_remove:
                print('sending waiting packets')
                self.send(item[0])
    
    def swapEther(self, pkt):
        pkt[Ether].dst = pkt[Ether].src
        pkt[Ether].src = self.router.intfs[pkt[CPUMetadata].srcPort].mac
    
    def swapIP(self, pkt):
        tmp = pkt[IP].dst
        pkt[IP].dst = pkt[IP].src
        pkt[IP].src = tmp
    
    def handleICMP(self, pkt):
        if pkt[ICMP].type == ICMP_TYPE_REQUEST and pkt[IP].dst in self.switchIPs:
            pkt[ICMP].type = ICMP_TYPE_REPLY
            pkt[IP].ttl = 99
            self.swapIP(pkt)
            self.swapEther(pkt)
            self.send(pkt)
        elif pkt[IP].dst not in self.switchIPs:
            pkt[Ether].src = self.router.intfs[pkt[CPUMetadata].srcPort].mac
            self.send(pkt)
            

    def handlePkt(self, pkt):
        # pkt.show2()
        assert CPUMetadata in pkt, "Should only receive packets from switch with special header"

        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1: return

        # Handling ARP packets
        if ARP in pkt:
            # if pkt[ARP].pdst in self.switchIPs:
            self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
            self.addArpEntry(pkt[ARP].psrc, pkt[ARP].hwsrc)
            
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)
                
        # Handle IP packets
        elif IP in pkt:
            if ICMP in pkt:
                self.handleICMP(pkt)
            if PWOSPF in pkt:
                self.ospfHelper.handlePacket(pkt)
        else:
            print("Not an IP packet! Dropping...")
            
    def sendArp(self, ip, port):
        print('Sending ARP...')
        intf = self.router.intfs[1]
        out_intf = self.router.intfs[port]
        pkt = Ether(src=intf.mac, dst='ff:ff:ff:ff:ff:ff', type=TYPE_CPU_METADATA) / CPUMetadata(
            origEtherType=ETHER_TYPE_ARP, outPort=port)
        pkt = pkt / ARP(hwsrc=out_intf.mac, hwdst='ff:ff:ff:ff:ff:ff', psrc=out_intf.ip, pdst=ip, op=ARP_OP_REQ)
        self.send(pkt)
        

    def findRouting(self, ip):
        for subnet, prefixLen in self.routing_entries.keys():
            maskedIP = self.ospfHelper.truncate(ipaddress.ip_address(ip), prefixLen)
            if maskedIP == subnet:
                return self.routing_entries[(subnet, prefixLen)][0]
        return 0
            
    

    def send(self, *args, **override_kwargs):
        pkt = args[0]
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        # Check for routing entries if packet is not OSPF
        if IP in pkt and PWOSPF not in pkt:
            port = self.findRouting(pkt[IP].dst)
            if (port == 0):
                return # drop the packet
            elif (pkt[IP].dst not in self.arp_entries):
                with self.arpLock:
                    self.waitingList.append([pkt, self.arp_timeout])
                self.sendArp(pkt[IP].dst, port)
                return
        
        pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        # pkt.show2()
        sendp(*args, **kwargs)

    def run(self):
        sniff(iface=self.iface, prn=self.handlePkt, stop_event=self.stop_event)

    def start(self, *args, **kwargs):
        super(RouterController, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(RouterController, self).join(*args, **kwargs)
