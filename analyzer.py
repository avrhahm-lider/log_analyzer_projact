import checks
def return_ip_set(data: list[list[str]]):
    return set(socket[1] for socket in data)

def number_of_inquiries(data: list[list[str]]):
    return {ip: sum(1 for i in data if i[1] == ip) for ip in return_ip_set(data)}
print(len(number_of_inquiries(checks.extract_cvs_file(checks.path))))


