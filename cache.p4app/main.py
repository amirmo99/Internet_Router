import imp
from p4app import P4Mininet
from mininet.topo import SingleSwitchTopo
from mininet.cli import CLI
import sys
import time

topo = SingleSwitchTopo(2)
net = P4Mininet(program='cache.p4', topo=topo)
net.start()

s1, h1, h2 = net.get('s1'), net.get('h1'), net.get('h2')

# Creating some cache values
myCache = [(3, 33), (9, 14), (19, 128)]

# TODO Populate IPv4 forwarding table
table_entries = []
for i in [1, 2]:
    table_entries.append(dict(table_name='MyIngress.ipv4_lpm',
                        match_fields={'hdr.ipv4.dstAddr': ["10.0.0.%d" % i, 32]},
                        action_name='MyIngress.ipv4_forward',
                        action_params={'dstAddr': net.get('h%d'%i).intfs[0].MAC(),
                                          'port': i}))  

# TODO Populate the cache table
for key, value in myCache:
    table_entries.append(dict(table_name='MyIngress.cache_table',
                        match_fields={'hdr.reqHdr.key': key},
                        action_name='MyIngress.reply_value',
                        action_params={'val': value}))

# Now, we can test that everything works
sw = net.get('s1')
for table_entry in table_entries:
    sw.insertTableEntry(table_entry)

sw.printTableEntries()

loss = net.pingAll()
assert loss == 0  


# Start the server with some key-values
server = h1.popen('./server.py 1=11 2=22', stdout=sys.stdout, stderr=sys.stdout)
time.sleep(0.4) # wait for the server to be listenning

# CLI(net)

out = h2.cmd('./client.py 10.0.0.1 1') # expect a resp from server
assert out.strip() == "11"
out = h2.cmd('./client.py 10.0.0.1 1') # expect a value from switch cache (registers)
assert out.strip() == "11"
out = h2.cmd('./client.py 10.0.0.1 2') # resp from server
assert out.strip() == "22"
out = h2.cmd('./client.py 10.0.0.1 3') # from switch cache (table)
assert out.strip() == "33"
out = h2.cmd('./client.py 10.0.0.1 9') # from switch cache (table)
assert out.strip() == "14"
out = h2.cmd('./client.py 10.0.0.1 19') # from switch cache (table)
assert out.strip() == "128"
out = h2.cmd('./client.py 10.0.0.1 123') # resp not found from server
assert out.strip() == "NOTFOUND"

server.terminate()
