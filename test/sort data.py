import json
import datetime

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

# Replace 'your_json_file.json' with the actual path to your JSON file
json_file_path = 'dionaea.json'
result = get_last_hour_data(json_file_path)

# Print the result
#print(result)

unique = { each['src_ip'] : each for each in result }.values()

for uni in unique:
    #print (uni['src_ip'])
    f = open('list.txt', "a")
    f.write(uni + "\n")
    f.close()