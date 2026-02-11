from reader import extract_cvs_file

def external_ip_extraction(data: list[list[str]]):
    return [socket[1] for socket in data if socket[1].split(".")[0] != "10" and socket[1].split(".")[0]+socket[1].split(".")[1] != "192168" ]

def external_sensitive_ports(data: list[list[str]]):
    sensitive_ports = {"22","3389","23"}
    return [socket for socket in data if socket[-3] in sensitive_ports]

def external_big_packets(data: list[list[str]]):
    return [socket for socket in data if int(socket[-1]) > 5000]

def package_labeling(data: list[list[str]]):
    return [(socket,"LARGE") if int(socket[-1]) > 5000 else (socket,"NORMAL") for socket in data]
