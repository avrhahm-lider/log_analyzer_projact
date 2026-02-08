import checks
def return_ip_set(data: list[list[str]]):
    return set(socket[1] for socket in data)

def number_of_inquiries(data: list[list[str]]):
    return {ip: sum(1 for i in data if i[1] == ip) for ip in return_ip_set(data)}


def protocol(data: list[list[str]]):
    return {socket[-3]: socket[-2] for socket in data}
print(protocol(checks.extract_cvs_file(checks.path)))

