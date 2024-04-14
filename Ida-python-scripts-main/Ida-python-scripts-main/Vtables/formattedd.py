import json
import time
import asyncio

# Define the function to extract names from each line
def extract_names(line):
    # Split the line by tabs
    parts = line.split('\t')
    # Extract the similarities and confidence values
    similarities = parts[0]
    confidences = parts[1]
    # Extract the first and second names
    first_name = parts[4]
    first_address = parts[3]
    second_name = parts[6]  # Adjusted index to get the function name
    second_address = parts[5]  # Adjusted index to get the function name
    algorithms = parts[8]
    return {'similarities': similarities, 'confidences': confidences, 'first_name': first_name, 'first_address': first_address, 'second_name': second_name, 'second_address': second_address, 'algorithms': algorithms}

async def process_lines(chunk):
    # Initialize an empty list to store extracted names
    names_list = []
    # Iterate over each line and extract names
    for line in chunk:
        names_list.append(extract_names(line))
    return names_list

def save_to_json(data):
    # Write the extracted names to a JSON file
    with open('C:/Users/tonyt/Videos/python-scriptsida/Ida-python-scripts-main/Ida-python-scripts-main\Vtables/extracted_names.json', 'w') as json_file:
        json.dump(data, json_file, indent=4)

async def main():
    start_time = time.time()

    # Read the content of the file
    with open('C:/Users/tonyt/Videos/python-scriptsida/Ida-python-scripts-main/Ida-python-scripts-main/Vtables/result.txt', 'r') as file:
        lines = file.readlines()

    # Calculate the number of chunks
    num_chunks = (len(lines) + 999) // 1000

    # Process lines in batches of 1000 asynchronously
    tasks = []
    for i in range(num_chunks):
        chunk = lines[i * 1000: (i + 1) * 1000]
        tasks.append(process_lines(chunk))
    
    results = await asyncio.gather(*tasks)

    # Flatten the list of lists
    names_list = [item for sublist in results for item in sublist]

    # Save to JSON
    save_to_json(names_list)

    end_time = time.time()
    print(f"Names extracted and saved to 'extracted_names.json' in {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    asyncio.run(main())
