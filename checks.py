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
print(extract_cvs_file(path))
def external_ip_extraction(data: list[list[str]]):
    ip_extrac =[]
    for socket in data:
        ip = socket[1].split(".")
        if ip[0] != "10" and ip[0]+ip[1] != "192168":
            ip_extrac.append(ip)
    return ip_extrac
print(external_ip_extraction(extract_cvs_file(path)))
