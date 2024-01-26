def find_and_save_non_duplicates(variable, file_path):
    # Read the content of the text file
    with open(file_path, 'r') as file:
        file_content = file.read().splitlines()

    # Convert the variable and file content to sets
    variable_set = set(variable)
    file_content_set = set(file_content)

    # Find the elements that are unique to the variable
    non_duplicates = variable_set - file_content_set

    # Save the non-duplicate values to the same text file
    with open(file_path, 'w') as file:
        if non_duplicates:
            file.write("Non-duplicate values:\n")
            for value in non_duplicates:
                file.write(str(value) + '\n')
        else:
            file.write("No non-duplicate values found.")

# Example usage:
variable = 
file_path = 'your_text_file.txt'

find_and_save_non_duplicates(variable, file_path)