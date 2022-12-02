# Router

All the required parts are done, except PWOSPF routing entry timeouts! Sample topology is as follows. We have 3 routers names s1-s3 and 4 hosts h1-h4.

                                   -----s3 --- h4
                                  |     |
Network Topology:         h1 --- s1 --- s2 --- h2
                                  |
                                 h3


- This project is tested in my home computer which runs WSL inside windows, and uses python3. Although, I had to install networkx version 2.2 because only this version worked with python2!!! 
- To save and process on the global topology we use networkx, which is a package for studying networks. So upon starting the program networkx pip package is going to be installed inside the docker container and then the mininet network is run.

Notes:
- Static routes can be added inside main file.
- Arp requests are sent if the arp entry is not available.
- Arp entries will be removed after a certain amount of time
- Arp requests with destination in router addresses are handled by the controller
- I have a table in the egress that sets the src mac address when forwarding a packet out
- To forward Arp packets, fwd_l2 table is created inside the p4
- If the output port is determined by the controller, the data plane just forwards the packet out of that port without doing an ARP request
- ICMP echo requests are handled by the controller if the destination is the controller itself
- packets with ttl=0 or wrong checksum are dropped
- Upon receving LSU packets with new data, ospf_helper removes all non-static entries inside the routing table, computes the new routes, and insert routing entries