import idaapi as api
import idautils as utils
import idc as idc
import json


input_path = api.ask_file(True, "*.json", "Input file for name finding")
output_path = api.ask_file(False, "*.json", "Output file for updated names")

with open(input_path, "r") as file:
    data = json.load(file)

for entry in data:
    second_address = int(entry["second_addres"], 16)
    name = idc.get_name(second_address)
    entry["second_name"] = name if name else f"Unknown_{entry['second_addres']}"

with open(output_path, "w") as outfile:
    json.dump(data, outfile, indent=4)

api.msg("\nUpdated names have been written to the output file.")
