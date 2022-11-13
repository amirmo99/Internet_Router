from p4app import P4Mininet
from my_topo import DemoTopo
from controller import RouterController
from mininet.cli import CLI

# Port 1 (h1) is reserved for the CPU.

topo = DemoTopo()
net = P4Mininet(program='router.p4', topo=topo)
net.start()
topo.setRouterIPs(net)

sw = net.get('s1')
# print (sw.intfs.items())

# Start the MAC learning controller
cpu = RouterController(sw)
cpu.start()

h2, h3 = net.get('h2'), net.get('h3')
        
CLI(net)


# print (h2.cmd('arping -c1 10.0.0.3'))

# print (h3.cmd('ping -c1 10.0.0.2'))

# These table entries were added by the CPU:
sw.printTableEntries()