import checks
from datetime import time
def return_ip_set(data: list[list[str]]):
    return set(socket[1] for socket in data)

def number_of_inquiries(data: list[list[str]]):
    return {ip: sum(1 for i in data if i[1] == ip) for ip in return_ip_set(data)}


def protocol(data: list[list[str]]):
    return {socket[-3]: socket[-2] for socket in data}

def sensitive_port_list(data: list[list[str]]):
    return set(ip[1] for ip in data)

def large_packet_set(data: list[tuple[list[str],str]]):
    return set((stat[0][1],stat[1]) for stat in data if stat[1] == "LARGE" )

def time_set(data: list[list[str]]):
    return set(ip[1] for ip in data if  0 < int(ip[0][-8:].replace(":","")) < 600000)

def dict_suspicious_ip(data: list[list[str]]):
    dict1 = {}
    a = checks.external_ip_extraction(data)
    b = sensitive_port_list(checks.external_sensitive_ports(data))
    c = large_packet_set(checks.external_big_packets(data))
    d = time_set(data)

    for ip in return_ip_set(data):
        arr = []
        if ip in a:
            arr.append("EXTERNAL_IP")
        if ip in b:
            arr.append("SENSITIVE_PORT")
        if ip in c:
            arr.append("LARGE_PACKET ")
        if ip in d:
            arr.append("NIGHT_ACTIVITY")
        dict1[ip] = arr
    return dict1

def map_num_of_sus(data:dict):
    return {key: val for key,val in data.items() if len(val) > 1 }

def hourly_rescue(timestamp:list[str]):
    return list(map(lambda x: x[-8],timestamp))

def conversion_kilobits(byte_list:list[str]):
    return list(map(lambda x : x/ 1024,byte_list))

def external_sensitive_port(data :list[list[str]]):
    sensitive_ports = {"22", "3389", "23"}
    return list(filter(lambda x : x[-3] in sensitive_ports,data))