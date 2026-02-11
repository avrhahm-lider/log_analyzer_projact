from analyzer import *
from reader import extract_cvs_file

def suspicions_above_two(data :list[list[str]]):
    return filter(lambda x : len(x) >= 1,map(checking_suspicions_row,data))

def row_above_two_suspicions(data, func):
    return filter(lambda x : len(list(func(x))) > 1,data)

def line_and_type_suspicion(data):
    return map(lambda x :(x,checking_suspicions_row(x)),data)

def count(data):
    return sum(1 for socket in data if len(socket[1]) > 0)
l = extract_cvs_file("network_traffic.log")
sus = row_above_two_suspicions(l,checking_suspicions_row)
de = line_and_type_suspicion(sus)
c = count(de)
print(c)