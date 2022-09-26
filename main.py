from os import path
from netifaces import interfaces, ifaddresses
import re

# CONFIG
abuse_ips_dict = {}
abuse_subnets_dict = {}
white_listed_ips = ['127.0.0.1']
auto_whitelist_own_ips = True
# logfiles = ['/var/log/messages', '/var/log/auth.log'] 
logfiles = ['./messages.log', './auth.log'] 
abuse_patterns = ['[UFW BLOCK]', 'Failed password for']
ip_attacks_thershold = 2 #10
subnets_attackers_ips_thershold = 5 #50
network_ip_attacks_thershold = 2 #50
output_ips_file = './abuse_ips.txt'

src_ip_pattern = re.compile(r'SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

if auto_whitelist_own_ips:
    for interface in interfaces():
        for _, link in ifaddresses(interface).items():
            addr = link[0]['addr']
            if ip_pattern.search(addr) and addr not in white_listed_ips:
                white_listed_ips.append(addr)

# print(white_listed_ips)

def get_subnet(ip_addr : str) -> str:
    assert ip_pattern.search(ip_addr)
    return '.'.join(ip_addr.split('.')[:3]) + '.0/24'

def address_in_subnet(ip_addr : str, subnet : str) -> bool:
    assert ip_addr != ''
    assert subnet != ''
    return get_subnet(ip_addr) == subnet

for logfile in logfiles:
    with open(logfile) as fh:
        fstring = fh.readlines()

    for line in fstring:
        for abuse_pattern in abuse_patterns:     
            if abuse_pattern in line and src_ip_pattern.search(line):   
                # if src_ip_pattern.search(line):
                    ip = src_ip_pattern.search(line)[0].split('SRC=')[1]
                    if ip not in white_listed_ips:
                        if abuse_ips_dict.get(ip):
                            abuse_ips_dict[ip] = abuse_ips_dict.get(ip) + 1                                            
                        else:
                            abuse_ips_dict[ip] = 1

# let in new array only IP over thershold and fill subnets list
new_abuse_ips_dict = {}
for ip, count in abuse_ips_dict.items():
    if count > ip_attacks_thershold:
        new_abuse_ips_dict[ip] = count
    # contar IP en subred con mas de 5 ataques registrados
    if count > network_ip_attacks_thershold:
        subnet = get_subnet(ip)
        # print(subnet)
        if subnet not in white_listed_ips:
            if abuse_subnets_dict.get(subnet):
                abuse_subnets_dict[subnet] = abuse_subnets_dict.get(subnet) + 1                                            
            else:
                abuse_subnets_dict[subnet] = 1

abuse_subnets_list = []
for subnet, count in abuse_subnets_dict.items():
    # print(f"subnet {subnet} count {count}")
    if count > subnets_attackers_ips_thershold:
        abuse_subnets_list.append(subnet)

to_save_ips = []
loaded_ips = []

if path.exists(output_ips_file):
    with open(output_ips_file) as f:
        loaded_ips=f.read().splitlines()

with open(output_ips_file, 'w') as f:
    for ip, count in new_abuse_ips_dict.items():
        if ip not in loaded_ips:
            loaded_ips.append(ip)

    for subnet in abuse_subnets_list:
            if subnet not in loaded_ips:
                to_save_ips.append(subnet)

    for ip in loaded_ips:
        if not get_subnet(ip) in to_save_ips:
            # dont insert ip if its subnets exists        
            to_save_ips.append(ip)

    print(to_save_ips)

    for ip in to_save_ips:
        f.write(f'{ip}\n')