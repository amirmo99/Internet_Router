import time
from threading import Thread, Timer
import ipaddress
from headers import *
from scapy.all import ARP, ICMP, IP, Ether, Packet, Raw

from consts import *
import io

# import os
# os.system('pip install networkx==2.2')
# import networkx as nx


class OSPFHelper:
    def __init__(self, controller, areaID, hello_int=30, lsuint=30):
        self.arp_table = {}
        self.neighborsTTL = {}
        self.global_routes = {}
        self.controller = controller
        self.router = controller.router
        self.areaID = areaID
        self.hello_int = hello_int
        self.lsuint = lsuint
        
        self.LSUsequence = 0
        
        self.control_intf = controller.router.intfs[1]
        self.routerID = int(ipaddress.ip_address(self.control_intf.ip))
        self.neighbor_timeout = 3 * hello_int
        
        self.addInitialNeighbors()
        Timer(5, self.startHello).start()
        Timer(10, self.startLSU).start()
        # Timer(2, self.timeoutTimer).start()
    
    def addInitialNeighbors(self):
        for port, _ in self.router.intfs.items():
            if port >= 2:
                self.addNeighbor(port, '0.0.0.0', 99999)
                subnet, mask, prefixLen = self.getSubnetAndMask(port)
                self.controller.addRoutingEntry(subnet, prefixLen, port, '0.0.0.0')
        
    def handlePacket(self, pkt):
        if pkt[PWOSPF].type == PWOSPF_TYPE_HELLO:
            self.handleHelloPacket(pkt)
        elif pkt[PWOSPF].type == PWOSPF_TYPE_LSU:
            self.handleLSUPacket(pkt)
        else:
            print('Unkown PWOSPF type received, dropping...')
    
    def handleHelloPacket(self, pkt):
        interface = self.router.intfs[pkt[CPUMetadata].srcPort]
        
        routerID = pkt[PWOSPF].routerID
        payload = io.BytesIO(bytes(pkt[Raw]))
        netMask = str(ipaddress.ip_address(payload.read(4)))
        helloInt = payload.read(2)
        
        print('Hello packet data received at ID={}: '.format(ipaddress.ip_address(self.routerID)))
        print(' RouterID: {}, netmask: {}, helloInt: {}'.format(ipaddress.ip_address(pkt[PWOSPF].routerID), netMask, helloInt))
        
        if (netMask == self.truncate("255.255.255.255", int(interface.prefixLen)) and
                    int.from_bytes(helloInt, 'big') == self.hello_int):
            self.addNeighbor(pkt[CPUMetadata].srcPort, routerID, self.neighbor_timeout)
        else:
            print("helloInt or netMask does not match!!!")
    
    def handleLSUPacket(self, pkt):
        interface = self.router.intfs[pkt[CPUMetadata].srcPort]
        
        routerID = pkt[PWOSPF].routerID
        payload = io.BytesIO(bytes(pkt[Raw]))
        
        seq = int.from_bytes(payload.read(2), 'big')
        ttl = int.from_bytes(payload.read(2), 'big')
        n = int.from_bytes(payload.read(4), 'big')
        
        data = {}
        for i in range(n):
            subnet = str(ipaddress.ip_address(payload.read(4)))
            mask = str(ipaddress.ip_address(payload.read(4)))
            id = str(ipaddress.ip_address(payload.read(4)))
            data[i] = {'subnet': subnet, 'mask': mask, 'id': id}
            
        print('LSU packet data received at ID={}: '.format(ipaddress.ip_address(self.routerID)))
        print(data)
    
    def linkStateUpdate(self):
        pass

    def getSubnetAndMask(self, port):
        intf = self.router.intfs[port]
        subnet = self.truncate(intf.ip, int(intf.prefixLen))
        mask = self.truncate('255.255.255.255', int(intf.prefixLen))
        return subnet, mask, int(intf.prefixLen)
    
    def truncate(self, ip, prefixLen: int):
        """ 
        Masks the ip with the appropriate prefix length
        """
        assert (prefixLen < 32 and prefixLen >= 0)
        shift = 32 - prefixLen
        ip_l = int(ipaddress.ip_address(ip))
        masked_l = (ip_l >> shift) << shift
        return str(ipaddress.ip_address(masked_l))
    
    def addNeighbor(self, port, routerID, ttl):
        assert port > 1
        if port not in self.neighborsTTL:
            self.neighborsTTL[port] = {}
        
        id = str(ipaddress.ip_address(routerID))
        self.neighborsTTL[port][id] = ttl
    
    def timeoutTimer(self):
        seconds = 10
        Timer(seconds, self.timeoutTimer).start()
        
        print('neighbors of {}:'.format(self.routerID))
        for port in self.neighborsTTL.keys():
            subnet, mask, _ = self.getSubnetAndMask(port)
            for id in self.neighborsTTL[port].keys():
                self.neighborsTTL[port][id] -= seconds
                print('subnet = {}, mask = {}, routerID = {}, ttl = {}'.format(subnet, mask, id, self.neighborsTTL[port][id]))
        
    
    def genHello(self, port, intf):
        # Creating the hello packet data
        prefixLen = 32 - int(intf.prefixLen)
        mask = ((0xFFFFFFFF >> prefixLen) << prefixLen).to_bytes(4, 'big')
        hello = self.hello_int.to_bytes(2, 'big')
        padding = (0).to_bytes(2, 'big')
        
        # Constructing the packet headers
        pkt = Ether(src=self.control_intf.mac, dst='ff:ff:ff:ff:ff:ff', type=TYPE_CPU_METADATA) / CPUMetadata(
            origEtherType=ETHER_TYPE_IP, outPort=port)
        pkt = pkt / IP(src=self.control_intf.ip, dst=ALLSPFRoutersIP, proto=IP_PROTO_PWOSPF) 
        pkt = pkt / PWOSPF(version=2, type=PWOSPF_TYPE_HELLO, routerID=self.routerID, areaID=self.areaID,
                           auType=0, authentication=0, totalLen=24)
        pkt = pkt / Raw(mask+hello+padding)
        return pkt   
    
    def startHello(self):
        Timer(self.hello_int, self.startHello).start()
        # Send hello on each interface
        for port, intf in self.router.intfs.items():
            if port >= 2:
                pkt = self.genHello(port, intf)
                self.controller.send(pkt)
                
    def genLSUData(self):
        res = b''
        n = 0
        for port in self.neighborsTTL.keys():
            for id in self.neighborsTTL[port].keys():
                subnet, mask, prefixLen = self.getSubnetAndMask(port)
                res += int(ipaddress.ip_address(subnet)).to_bytes(4, 'big')
                res += int(ipaddress.ip_address(mask)).to_bytes(4, 'big')
                res += int(ipaddress.ip_address(id)).to_bytes(4, 'big')
                n += 1
        return n, res
                
    
    def genLSU(self, port, dstIP):
        # Creating the LSU packet data
        n, data = self.genLSUData()
        seq = self.LSUsequence.to_bytes(2, 'big')
        ttl = (64).to_bytes(2, 'big')
        
        
        # Constructing the packet headers
        pkt = Ether(src=self.control_intf.mac, type=TYPE_CPU_METADATA) / CPUMetadata(
            origEtherType=ETHER_TYPE_IP, outPort=port)
        pkt = pkt / IP(src=self.control_intf.ip, dst=dstIP, proto=IP_PROTO_PWOSPF) 
        pkt = pkt / PWOSPF(version=2, type=PWOSPF_TYPE_LSU, routerID=self.routerID, areaID=self.areaID,
                           auType=0, authentication=0, totalLen=24)
        pkt = pkt / Raw(seq + ttl + n.to_bytes(4, 'big') + data)
        return pkt   
                
    def startLSU(self):
        Timer(self.lsuint, self.startLSU).start()
        # Send LSU on each interface
        for port, intf in self.router.intfs.items():
            if port >= 2:
                for id in self.neighborsTTL[port].keys():
                    if id != '0.0.0.0':
                        pkt = self.genLSU(port, dstIP=id)
                        self.controller.send(pkt)
        self.LSUsequence += 1
        

