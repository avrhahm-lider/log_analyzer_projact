import csv

def extract_cvs_file(file_path):
    try:
        with open(file_path, "r") as f:
            r = csv.reader(f)
            for row in r:
                yield row

    except FileNotFoundError as e:
        print(f"Error {e}")

print((extract_cvs_file("network_traffic.log")))