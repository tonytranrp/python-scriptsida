import idautils
import idadex
import ctypes
import json
import idaapi as api

def get_structures():
    structures = []
    for idx, sid, name in idautils.Structs():
        structure = {"Name": name, "Members": []}
        for offset, member_name, size in idautils.StructMembers(sid):
            structure["Members"].append({"Offset": offset, "Name": member_name, "Size": size})
        structures.append(structure)
    return structures

def main():
    # Ask user for the output file path
    path = api.ask_file(True, "*.json", "Output file for structures dump")
    if not path:
        print("No output file selected.")
        return

    structures = get_structures()
    with open(path, "w") as f:
        json.dump(structures, f, indent=4)
    print(f"Structure types dumped to '{path}'")

if __name__ == "__main__":
    main()
