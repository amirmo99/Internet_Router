---
title: P4 Internet_Router
author: Amirmohammad Nazari
date: Oct 7, 2022
---
# Amirmohammad Nazari
GitHub repository for the "Building an Internet Router" course

# Starter Project: Key-Value Service
For this assignment, I am using the latest version of the RC-2.0.0 branch of P4aApp, and my system uses python3. My implementation details are as follows:
## Parser
- Two states named check_request and check_header are responsible for checking the UDP header source and destination ports and finding out if the packet is a request or response or none of them. 
- Two headers are defined for requests and responses, named reqHdr and resHdr respectively.

## Ingress
- I have two registers: myCache & myCache_check. The latter has 1-bit values and is used to show whether the key is available in the switch cache or not. The former holds 32-bit values and stores the cached values.
- We have a forwarding table same as basic.p4 example. We also have a cache table that holds key-values that are cached due to a previously received message from the server.
- New action is defined: reply_value. This action inputs a value and replies to the message with the value set in its resHdr.
- In the apply{ } section, if there is a reqHdr and key in the packet we try to find the cached value for that key first in the switch register and then in the cache table. If there is a match we reply to the message with the cached value, and if not, the packet is forwarded to its destination.

## Deparser
- Here we just emit all the valid headers.