import idautils as utils
import idc as idc
import idaapi as api
import json

def get_function_start(ea):
    # Get the start address of the function containing the given address
    func = api.get_func(ea)
    if func:
        start = func.start_ea
        return start
    return None

def get_possible_xrefs(start_address):
    xrefs_list = []

    # Get inputted function names
    input_func_names = []
    start = get_function_start(start_address)
    if start:
        input_func_name = idc.get_func_name(start)
        input_demangled_name = idc.demangle_name(input_func_name, api.cvar.inf.long_demnames)
        input_func_names.append(input_demangled_name)

        # Get xrefs to the specified address
        xrefs = utils.XrefsTo(start_address)

        # Iterate through each xref
        for xref in xrefs:
            # Get the reference address and type
            ref_address = xref.frm

            # Add the reference address to the list
            xrefs_list.append({"Address": hex(ref_address), "Name": idc.get_func_name(ref_address)})

    return input_func_names, xrefs_list


# Example usage:
start_address = 0x142033F70
input_func_names, xrefs_results = get_possible_xrefs(start_address)

# Prepare data for JSON format
output_data = {
    "Input address": hex(start_address),
    "Inputted function names": input_func_names,
    "Xrefs": xrefs_results
}

# Write xref results to a JSON file
output_file = "C:/Users/tonyt/Videos/python-scriptsida/Ida-python-scripts-main/Ida-python-scripts-main/Vtables/xrefs.json"
with open(output_file, "w") as f:
    json.dump(output_data, f, indent=4)

# Notify completion
print(f"Xrefs results written to '{output_file}'")
