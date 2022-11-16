import time
from threading import Thread, Timer
import ipaddress
from headers import *
from scapy.all import ARP, ICMP, IP, Ether, Packet, Raw

from consts import *
import io
import networkx as nx


class OSPFHelper:
    def __init__(self, controller, routerID, areaID, hello_int=30, lsuint=30):
        self.controller = controller
        self.router = controller.router
        self.routerID = routerID
        self.areaID = areaID
        self.control_intf = controller.router.intfs[1]
        self.hello_int = hello_int
        self.lsuint = lsuint
        # self.topology = nx.Graph()
        # self.topology.add_node(routerID, ip=self.main_intf)
        self.neighbor_timeout = 3 * hello_int
        # self.routing_table = {}
        # self.arp_table = {}
        self.neighbors = {}
        Timer(5, self.startHello).start()
    
    def handlePacket(self, pkt):
        pass
        # file = io.BytesIO(b'this is a byte string')
        #  file.read(2)   
    
    def linkStateUpdate():
        pass

    def truncate(self, ip, prefixLen):
        """ 
        Masks the ip with the appropriate prefix length
        """
        assert (prefixLen < 32 and prefixLen >= 0)
        shift = 32 - prefixLen
        ip_l = int(ipaddress.ip_address(ip))
        masked_l = (ip_l >> shift) << shift
        return str(ipaddress.ip_address(masked_l))
    
    def addNeighbor(self, ip, mac, port):
        timestamp = time.time()
        
        assert port <= len(self.router.intfs)
        
        if port not in self.neighbors:
            self.neighbors[port] = {}

        if ip not in self.neighbors[port]:
            self.neighbors[port][ip] = timestamp
            prefixLen = int(self.router.intfs[port].prefixLen)

            self.router.insertTableEntry(table_name='MyIngress.routing_table',
                    match_fields={'hdr.ipv4.dstAddr': [self.truncate(ip, prefixLen), prefixLen]},
                    action_name='MyIngress.set_nhop',
                    action_params={'port': [port], 'ipv4': [ip]})
            
            self.router.insertTableEntry(table_name='MyIngress.arp_table',
                    match_fields={'meta.routing.nhop_ipv4': [ip]},
                    action_name='MyIngress.set_dmac',
                    action_params={'dmac': mac})
        else:
            self.neighbors[port][ip] = timestamp
            
        print(self.neighbors)

    
    def genHello(self, port, intf):
        # Creating the hello packet data
        prefixLen = 32 - int(intf.prefixLen)
        mask = ((0xFFFFFFFF >> prefixLen) << prefixLen).to_bytes(4, 'big')
        hello = self.hello_int.to_bytes(2, 'big')
        
        # Constructing the packet headers
        pkt = Ether(src=self.control_intf.mac, dst='ff:ff:ff:ff:ff:ff', type=TYPE_CPU_METADATA) / CPUMetadata(
            origEtherType=ETHER_TYPE_IP, outPort=port)
        pkt = pkt / IP(src=self.control_intf.ip, dst=ALLSPFRouters, proto=IP_PROTO_PWOSPF) 
        pkt = pkt / PWOSPF(version=2, type=1, routerID=self.routerID, areaID=self.areaID,
                           auType=0, authentication=0, totalLen=24)
        pkt = pkt / Raw(mask+hello)
        print (mask+hello)
        return pkt   
    
    def startHello(self):
        Timer(self.hello_int, self.startHello).start()
        # Send hello on each interface
        for port, intf in self.router.intfs.items():
            if port >= 2:
                pkt = self.genHello(port, intf)
                self.controller.send(pkt)

