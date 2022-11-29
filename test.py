import ipaddress

def truncate(ip, prefixLen):
    assert (prefixLen < 32 and prefixLen >= 0)
    ip_l = int(ipaddress.ip_address(ip))
    shift = 32 - prefixLen
    res = (ip_l >> shift) << shift
    return str(ipaddress.ip_address(res))
    
    
def pad(message: bytes, length: int):
    if len(message) <= length:
        return (length - (len(message)))*b'0' + message
    

print(truncate('10.10.8.4', 24))

print(pad(b'1234', 8))

prefixLen = 8
mask = ((0xFFFFFFFF >> prefixLen) << prefixLen).to_bytes(4, 'big')
print(mask)