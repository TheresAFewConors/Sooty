import csv


def read_csv_ips(csv_file_path):
    csv_file = open(csv_file_path, 'r')
    csv_fields = csv.reader(csv_file)
    ip_list = {}
    for row in csv_fields:
        ip = row[0]
        ip_list[ip] = row

    csv_file.close()
    if(ip_list):
        return ip_list
