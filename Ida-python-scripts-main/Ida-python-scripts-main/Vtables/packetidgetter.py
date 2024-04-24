#you get the packetids in https://github.com/Mojang/bedrock-protocol-docs/blob/main/index.html # just go to file:///C:/Users/tonyt/Downloads/bedrock-protocol-docs-main/bedrock-protocol-docs-main/html/enums.html
# and just do ctr + a and ctr + c then paste it in the result and it will spit out into the zaa.cpp
def extract_packets(input_file, output_file):
    with open(input_file, 'r') as f:
        lines = f.readlines()

    with open(output_file, 'w') as f:
        current_enum_name = ""
        f.write("#include <iostream>\n\n")
        for line in lines:
            line = line.strip()
            if line:
                parts = line.split("\t")
                if len(parts) == 2:
                    enum_name, packet_info = parts
                    if enum_name != current_enum_name:
                        if current_enum_name:
                            f.write("\t};\n\n")
                        current_enum_name = enum_name
                        f.write("enum class " + enum_name + " : int {\n")
                    packet_name, packet_id = packet_info.split(" = ")
                    f.write("\t" + packet_name.strip() + " = " + packet_id.strip() + ",\n")
                else:  # Handle additional packet IDs for the same enum
                    packet_name, packet_id = line.split(" = ")
                    f.write("\t" + packet_name.strip() + " = " + packet_id.strip() + ",\n")
        f.write("\t};\n")

    # Remove the last comma from the last enum if present
    with open(output_file, 'r+') as f:
        data = f.read()
        f.seek(0, 0)
        f.write(data.replace(',\n\t};', '\n\t};'))

input_file = "C:/Users/tonyt/Videos/python-scriptsida/Ida-python-scripts-main/Ida-python-scripts-main/Vtables/result.txt"
output_file = "C:/Users/tonyt/Videos/python-scriptsida/Ida-python-scripts-main/Ida-python-scripts-main/Vtables/zaa.cpp"
extract_packets(input_file, output_file)
print("Packets enums generated successfully in", output_file)
