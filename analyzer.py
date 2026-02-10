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
    return list(map(lambda x: str(check_first_num(x[-8:-10])),timestamp))

def conversion_kilobits(byte_list:list[str]):
    return list(map(lambda x : x/ 1024,byte_list))

def external_sensitive_port(data :list[list[str]]):
    sensitive_ports = {"22", "3389", "23"}
    return list(filter(lambda x : x[-3] in sensitive_ports,data))

def happened_at_night(data :list[list[str]]):
    return list(filter(lambda x : 0 < check_first_num(x[0][-8:-6]) < 6,data))
def check_first_num(num:str):
    if int(num[0]) == 0:
        return int(num[1])
    return int(num)
sensitive_ports = {"22","3389","23"}
suspicion_checks = {
"EXTERNAL_IP": lambda x : x[1].split(".",1)[0] != "10" or x[1].split(".",2)[0]+x[1].split(".",1)[1] == "192168",
"SENSITIVE_PORT": lambda x : x[-3] in sensitive_ports,
"LARGE_PACKET": lambda x: int(x[-1]) > 5000,
"NIGHT_ACTIVITY": lambda x : 0 < check_first_num(x[0][-8:-6]) < 6 }
def checking_suspicions_row(row:list[str], sen_dict:dict = suspicion_checks):
    return [key for key , val in  sen_dict.items() if val(row)]

def above_two_suspicions(data :list[list[str]]):
    return list(filter(lambda x : len(x) >= 2,map(checking_suspicions_row,data)))
print(len(checks.extract_cvs_file(checks.path)))
print(len(above_two_suspicions(checks.extract_cvs_file(checks.path))))