from p4app import P4Mininet
from my_topo import DemoTopo
from controller import RouterController
from mininet.cli import CLI
from time import sleep

# Port 1 (h1) is reserved for the CPU.

topo = DemoTopo()
net = P4Mininet(program='router.p4', topo=topo, auto_arp=False)
net.start()
topo.initialize(net)

sw1 = net.get('s1') 
sw2 = net.get('s2') 
#print (sw1.intfs[1].prefixLen) # Attributes of intf: ip, mac, prefixLen

# Start the MAC learning controller
cpu1 = RouterController(sw1, routerID=1, areaID=1)
cpu2 = RouterController(sw2, routerID=2, areaID=2)
cpu1.start()
cpu2.start()

h1, h2 = net.get('h1'), net.get('h2')
        
CLI(net)

# print (h2.cmd('arping -c3 10.0.2.1'))
# print (h1.cmd('ping -c3 10.0.1.1'))

# sleep(20)
# These table entries were added by the CPU:
sw1.printTableEntries()
sw2.printTableEntries()