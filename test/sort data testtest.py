import json
import datetime
import os
import requests

def get_last_hour_data(json_file_path):
    # Read the JSON file
    list_json = []
    with open(json_file_path, 'r') as file:
        for line in file:
            list_json.append(json.loads(line))

    # Get the current time
    current_time = datetime.datetime.now()

    # Calculate the time 1 hour ago
    one_hour_ago = current_time - datetime.timedelta(hours=1)

    # Filter the data for the last 1 hour
    last_hour_data = [entry for entry in list_json if datetime.datetime.fromisoformat(entry['timestamp']) >= one_hour_ago]

    return last_hour_data

def find_non_duplicates(variable, file_path):
    # Read the content of the text file
    with open(file_path, 'r') as file:
        file_content = file.read().splitlines()

    # Convert the variable and file content to sets
    variable_set = set(variable)
    file_content_set = set(file_content)

    # Find the elements that are unique to the variable
    non_duplicates = variable_set - file_content_set

    # Convert the non-duplicate values back to a list
    non_duplicates_list = list(non_duplicates)

    return non_duplicates_list

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
                    #print(f"{engine}: {result['result']}")

                    data = result['result']
                    if data == "clean":
                        clean_index = clean_index + 1
                    else: 
                        malicious_index = malicious_index + 1 

                print("clean detection = ", clean_index)
                print("malicious detection = ", malicious_index)

                if malicious_index >=1 :
                    f = open(report, "a")
                    f.write(ip_address)
                    f.close()

            else:
                print("No information available for the IP address.")

        else:
            print("Error occurred while checking the IP address.")

    except requests.exceptions.RequestException as e:
        print("An error occurred during the request:", str(e))


#report = os.path.join('/var/html/www/', "report.txt")
report = 'report.txt'
# Replace 'your_json_file.json' with the actual path to your JSON file
json_file_path = 'dionaea.json'
result = get_last_hour_data(json_file_path)
api_key = '400aa01f5c5f0d64aaaa45ddbaa8840fcf48bc16ca63b27f37b3016dbdbb911f'



# Print the result
#print(result)

unique = { each['src_ip'] : each for each in result }.values()
for uni in unique:
    #print (uni['src_ip'])
    new_unique_datas = find_non_duplicates(uni['src_ip'], report) 
    check_ip_on_virustotal(new_unique_datas, api_key)





