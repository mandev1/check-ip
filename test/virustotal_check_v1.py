import json
import datetime
import os
import requests


def check_ip_on_virustotal(ip_address, api_key):
    clean_index = 0
    malicious_index = 0

    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'

    headers = {
        'x-apikey': api_key
    }

    try:
        response = requests.get(url, headers=headers)
        response_json = response.json()

        if response.status_code == 200:
            data = response_json['data']
            
            if 'attributes' in data:
                attributes = data['attributes']
                country = attributes.get('country', 'Unknown')
                last_analysis_results = attributes.get('last_analysis_results')
                
                print("IP Address:", ip_address)
                print("Country:", country)
                print("Last Analysis Results:")
                
                for engine, result in last_analysis_results.items():
                    data = result['result']
                    if data == "clean":
                        clean_index = clean_index + 1
                    else: 
                        malicious_index = malicious_index + 1 

                print("clean detection = ", clean_index)
                print("malicious detection = ", malicious_index)

                if malicious_index >=1 :
                    print("IP Address is malicious")
                    f = open(report_file_path, "a")
                    f.write(ip_address +"\n")
                    f.close()

            else:
                print("No information available for the IP address.")

        else:
            print("Error occurred while checking the IP address.")

    except requests.exceptions.RequestException as e:
        print("An error occurred during the request:", str(e))

def get_last_hour_data(json_file_path):
    list_json = []
    with open(json_file_path, 'r') as file:
        for line in file:
            list_json.append(json.loads(line))

    current_time = datetime.datetime.now()

    one_hour_ago = current_time - datetime.timedelta(hours=1)

    last_hour_data = [entry for entry in list_json if datetime.datetime.fromisoformat(entry['timestamp']) >= one_hour_ago]

    return last_hour_data


#next step : multi API
api_key = '400aa01f5c5f0d64aaaa45ddbaa8840fcf48bc16ca63b27f37b3016dbdbb911f'

#next step : multi json input
json_file_path = 'dionaea.json'

report_file_path = r'D:\report.txt'

if not os.path.isfile(report_file_path):
    w = open(report_file_path,"w")
    w.close()

w = open(report_file_path, "r")
data_files = w.read()
data_into_lists = data_files.splitlines()

value_into_lists = list()

#next step : get all json input
result = get_last_hour_data(json_file_path)
unique = { each['src_ip'] : each for each in result }.values()
for uni in unique:
    value_into_lists.append(uni['src_ip'])

compared_lists = list(set(value_into_lists).difference(data_into_lists))
data_into_lists.append(compared_lists)

for compared_list in compared_lists:
    check_ip_on_virustotal(compared_list, api_key)