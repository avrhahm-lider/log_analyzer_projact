import csv
from pathlib import Path
def extract_cvs_file(file_path):
    try:
        with open(file_path, "r") as f:
            r = csv.reader(f)
            return [row for row in r]
    except FileNotFoundError as e:
        print(f"Error {e}")
path = "C:\\Users\\1234\Downloads\log_analyzer_project-main\\network_traffic.log"

def external_ip_extraction(data: list[list[str]]):
    ip_extrac =[]
    for socket in data:
        ip = socket[1].split(".")
        if ip[0] != "10" and ip[0]+ip[1] != "192168":
            ip_extrac.append(ip)
    return ip_extrac
print(len(extract_cvs_file(path)))
def external_sensitive_ports(data: list[list[str]]):
    sensitive_ports = {"22","3389","23"}
    return [socket for socket in data if socket[-3] in sensitive_ports]
print(len(external_sensitive_ports(extract_cvs_file(path))))

def external_big_packets(data: list[list[str]]):
    return [socket for socket in data if int(socket[-1]) > 5000]


def package_labeling(data: list[list[str]]):
    labeling_list = []
    for socket in data:
        if int(socket[-1]) > 5000:
            socket.append("LARGE")
            labeling_list.append(socket)
        else:
            socket.append("NORMAL")
            labeling_list.append(socket)
    return labeling_list
print(package_labeling(extract_cvs_file(path)))