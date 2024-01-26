import csv

def sort_duplicate_values(csv_file_path, column_index):
    # Dictionary to store values and their occurrences
    value_counts = {}

    with open(csv_file_path, 'r') as file:
        reader = csv.reader(file)

        # Skip header if present
        next(reader, None)

        for row in reader:
            # Assuming the column_index is zero-based
            value = row[column_index]

            # If the value is already in the dictionary, it's a duplicate
            if value in value_counts:
                value_counts[value].append(row)
            else:
                value_counts[value] = [row]

    # Filter values with counts greater than 1 (duplicates)
    duplicates = {value: rows for value, rows in value_counts.items() if len(rows) > 1}

    # Sort the duplicates by value
    sorted_duplicates = sorted(duplicates.items())

    return sorted_duplicates

# Example usage:
csv_file_path = 'FGTADOM3-FGT_alog_from_2023-07-12_09_27_03_to_2024-01-08_09_27_02.csv'
column_index_to_check = 1  # Replace with the index of the column you want to check for duplicates

sorted_duplicates = sort_duplicate_values(csv_file_path, column_index_to_check)

if sorted_duplicates:
    print(f'Sorted duplicate values in column {column_index_to_check}:')
    for value, rows in sorted_duplicates:
        print(f'{value}:')
        for row in rows:
            print(f'  {row}')
else:
    print('No duplicate values found.')