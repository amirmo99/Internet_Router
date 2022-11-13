from mininet.topo import Topo

class DemoTopo(Topo):
    "Demo topology"

    def __init__(self, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        s1 = self.addSwitch('s1')
        
        h1 = self.addHost('h1', ip="10.0.1.10/24", mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip="10.0.2.10/24", mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip="10.0.3.10/24", mac='00:00:00:00:00:03')
        
        self.addLink(s1, h1)
        self.addLink(s1, h2)
        self.addLink(s1, h3)

    def setRouterIPs(self, net):
        s1 = net.get('s1')
        h1 = net.get('h1')
        h2 = net.get('h2')
        h3 = net.get('h3')
        
        s1.setIP('10.0.1.1/24', intf = 's1-eth1')
        s1.setMAC('00:00:00:00:01:01', intf = 's1-eth1')
        s1.setIP('10.0.2.1/24', intf = 's1-eth2')
        s1.setMAC('00:00:00:00:01:02', intf='s1-eth2')
        s1.setIP('10.0.3.1/254', intf = 's1-eth3')
        s1.setMAC('00:00:00:00:01:03', intf='s1-eth3')

        h1.setDefaultRoute("dev eth0 via 10.0.1.1")
        h2.setDefaultRoute("dev eth0 via 10.0.2.1")
        h3.setDefaultRoute("dev eth0 via 10.0.3.1")
        
        s1.cmd('s1 ip link set dev s1-eth2 arp off')
        s1.cmd('s1 ip link set dev s1-eth3 arp off')