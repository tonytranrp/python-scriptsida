import json

# Define the function to extract names from each line
def extract_names(line):
    # Split the line by tabs
    parts = line.split('\t')
    # Extract the first and second names
    first_name = parts[4]
    second_name = parts[6]  # Adjusted index to get the function name
    # Remove function arguments and surrounding angle brackets
    second_name = second_name.split('(')[0]  # Remove function arguments
    return first_name, second_name

# Read the content of the file
with open('C:/Users/tonyt/Downloads/Ida-python-scripts-main/Ida-python-scripts-main/Vtables/result.txt', 'r') as file:
    lines = file.readlines()

# Initialize an empty list to store extracted names
names_list = []

# Iterate over each line and extract names
for line in lines:
    first_name, second_name = extract_names(line)
    # Append the names to the list
    names_list.append({'first_name': first_name, 'second_name': second_name})

# Write the extracted names to a JSON file
with open('C:/Users/tonyt/Downloads/Ida-python-scripts-main/Ida-python-scripts-main/Vtables/extracted_names.json', 'w') as json_file:
    json.dump(names_list, json_file, indent=4)

print("Names extracted and saved to 'extracted_names.json'")
