from pathlib import Path
def extract_cvs_file(file_path):
    send_list =[]
    p = Path(file_path)
    txt = p.read_text()
    with open("csv_file.csv","w") as f:
        f.write(txt)
    try:
        with open("csv_file.csv", "r") as f1:
            sockets_list = f1.readlines()
            for socket in sockets_list:
                socket = socket[:-2]
                send_list.append(socket.split(","))
            return send_list
    except FileNotFoundError as e:
        print(f"Error {e}")
path = "C:\\Users\\1234\Downloads\log_analyzer_project-main\\network_traffic.log"
print(extract_cvs_file(path))
