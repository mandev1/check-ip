import requests

def check_ip_on_virustotal(ip_address, api_key):
    clean_index = 0
    malicious_index = 0
    unrated_index = 0
    #report = os.path.join('/var/html/www/', "report.txt")
    report = 'report.txt'

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
                    elif data == "unrated":
                        unrated_index = unrated_index + 1
                    else: 
                        malicious_index = malicious_index + 1 

                print(clean_index)
                print(unrated_index)
                print(malicious_index)

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


# Replace 'YOUR_API_KEY' with your actual VirusTotal API key
api_key = '400aa01f5c5f0d64aaaa45ddbaa8840fcf48bc16ca63b27f37b3016dbdbb911f'
list_ip_address = open("list.txt", "r")

for ip_address in list_ip_address:
    check_ip_on_virustotal(ip_address, api_key)