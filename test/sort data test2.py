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

w = open('list.txt', "r")
data_files = w.read()
data_into_lists = data_files.splitlines()
print (data_into_lists)
value_into_lists = list()
print ("\n")


# Replace 'your_json_file.json' with the actual path to your JSON file
json_file_path = 'dionaea.json'
result = get_last_hour_data(json_file_path)
unique = { each['src_ip'] : each for each in result }.values()
for uni in unique:
    value_into_lists.append(uni['src_ip'])

compared_lists = list(set(value_into_lists).difference(data_into_lists))
data_into_lists.append(compared_lists)


f = open('list.txt', "a")
for compared_list in compared_lists:
    f.write(str(compared_list) + "\n")
f.close()