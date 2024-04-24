import re
import os

def extract_structs_from_cpp(file_path):
    with open(file_path, 'r') as file:
        cpp_code = file.read()

    # Extract all struct definitions
    struct_definitions = re.findall(r'struct\s+(.*?)(?=\{)', cpp_code, re.DOTALL)

    return struct_definitions

def write_structs_to_files(struct_definitions, output_dir):
    for struct_def in struct_definitions:
        # Remove spaces from struct name for file naming
        struct_name = struct_def.replace(' ', '')
        struct_file_path = os.path.join(output_dir, f"{struct_name}.h")

        # Write struct definition to file
        with open(struct_file_path, 'w') as struct_file:
            struct_file.write(f"struct {struct_def} {{\n}};\n")

def main():
    cpp_file_path = r"C:/Users/tonyt/Videos/python-scriptsida/Ida-python-scripts-main/Ida-python-scripts-main/Vtables/chinaclient.h"
    output_dir = r"C:/Users/tonyt/Videos/python-scriptsida/Ida-python-scripts-main/Ida-python-scripts-main/Vtables/Filestructdump"

    # Ensure output directory exists, create if not
    os.makedirs(output_dir, exist_ok=True)

    # Extract struct definitions from the C++ file
    struct_definitions = extract_structs_from_cpp(cpp_file_path)

    # Write struct definitions to individual header files
    write_structs_to_files(struct_definitions, output_dir)

    print("Structures dumped to individual header files.")

if __name__ == "__main__":
    main()
