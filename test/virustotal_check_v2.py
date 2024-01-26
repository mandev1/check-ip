import json
import datetime
import os
import requests


def check_ip_on_virustotal(ip_address, api_key):
    clean_index = 0
    malicious_index = 0
    g = open(log_file_path, "a")

    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'

    headers = {
        'x-apikey': api_key
    }

    try:
        response = requests.get(url, headers=headers)
        response_json = response.json()

        if response.status_code == 200:
            data = response_json['data']

            data_time = datetime.datetime.now()
            g.write(str(data_time) + "\t")
            print(str(data_time) + "\n")

            if 'attributes' in data:
                attributes = data['attributes']
                country = attributes.get('country', 'Unknown')
                last_analysis_results = attributes.get('last_analysis_results')

                print("IP Address:", ip_address)
                print("Country:", country)
                print("Last Analysis Results:")
                g.write("IP Address:"+ip_address +"\t")
                g.write("Country:"+ country +"\t")
                g.write("Last Analysis Results:" +"\t" )

                for engine, result in last_analysis_results.items():
                    data = result['result']
                    if data == "clean":
                        clean_index = clean_index + 1
                    else:
                        malicious_index = malicious_index + 1

                print("clean detection = ", clean_index)
                print("malicious detection = ", malicious_index)
                g.write("clean detection = "+ str(clean_index) +"\t")
                g.write("malicious detection = "+ str(malicious_index) +"\t")

                if malicious_index >=1 :
                    print("IP Address is malicious")
                    g.write("Status: IP Address is malicious" )
                    g.close()
                    f = open(report_file_path, "a")
                    f.write(ip_address +"\n")
                    f.close()

            else:
                print("No information available for the IP address.")
                g.write("Status: No information available for the IP address.")
                g.close()
        else:
            print("Error occurred while checking the IP address.")
            g.write("Status: Error occurred while checking the IP address.")
            g.close()

    except requests.exceptions.RequestException as e:
        print("An error occurred during the request:", str(e))

def get_last_hour_data(json_file_path):
    list_json = []
    with open(json_file_path, 'r') as file:
        for line in file:
            list_json.append(json.loads(line))

    current_time = datetime.datetime.now()

    one_hour_ago = current_time - datetime.timedelta(hours=8)

    last_hour_data = [entry for entry in list_json if datetime.datetime.fromisoformat(entry['timestamp']) >= one_hour_ago]

    return last_hour_data



#api_key = 'e2c84cb967e64de6f4c2ad0fbdf33c0ab9d237effd11f34a21cbb49ef70a3309'
api_key = 'a9dd9e4c5e83bd34404e1fab2131432be1eff6875639cba1af2eb9e328e24d0d'

#Masukkan direktori json yang mau di scan
json_file_path = r'/data/dionaea/log/dionaea.json'
#Direktori untuk menyimpan hasil scan (web)
report_file_path = r'/var/www/html/report.txt'
#Direktori untuk menyimpan log
log_file_path = r'/home/itadmin/Scanning-VIrusTotal/log.txt'

if not os.path.isfile(report_file_path):
    w = open(report_file_path,"w")
    w.close()

if not os.path.isfile(report_file_path):
    y = open(log_file_path,"w")
    y.close()

w = open(report_file_path, "r")
data_files = w.read()
data_into_lists = data_files.splitlines()
print("Hasil Rekapan Data Keseluruhan:")
print(data_into_lists)
print("\n")

value_into_lists = list()
result = get_last_hour_data(json_file_path)
unique = { each['src_ip'] : each for each in result }.values()

for uni in unique:
    value_into_lists.append(uni['src_ip'])

print("Hasil Rekapan Dionaea 1 Jam yang lalu:")
print(value_into_lists)
print("\n")

compared_lists = list(set(value_into_lists).difference(data_into_lists))
if compared_lists !=[]:
    data_time = datetime.datetime.now()
    f = open(report_file_path,"a")
    f.write("# Last Update:" + str(data_time) + "\n")
    f.close()
data_into_lists.append(compared_lists)
print("Kumpulan IP Address Baru:")
print(compared_lists)
print("\n")

for compared_list in compared_lists:
    check_ip_on_virustotal(compared_list, api_key)
