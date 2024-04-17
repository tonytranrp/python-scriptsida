import idaapi as api
import idautils as utils
import idc as idc
import ida_bytes
import json

def get_function_bounds(ea):
    # Get the start and end addresses of the function containing the given address
    func = api.get_func(ea)
    if func:
        start = func.start_ea
        end = func.end_ea
        return start, end
    return None, None

def get_unique_signature(start, end):
    signature = ""
    addr = start
    while addr < end:
        # Disassemble the current instruction
        insn = utils.DecodeInstruction(addr)
        if insn:
            # Get the bytes of the instruction
            insn_bytes = ida_bytes.get_bytes(addr, insn.size)
            # Convert bytes to a signature format
            sig_part = " ".join(["{:02X}".format(byte) for byte in insn_bytes])
            # Append the signature part to the overall signature
            signature += sig_part + " "
            # Move to the next instruction
            addr += insn.size
        else:
            # If disassembly fails, move to the next byte
            addr += 1
    return signature.strip()

def get_offsets(func_ea):
    offsets = []
    func_disasm = idc.GetDisasm(func_ea)
    lines = func_disasm.split('\n')
    for line in lines:
        if "mov" in line and "rax, [rcx+" in line:
            offset = line.split("[rcx+")[1].split("h")[0]
            offsets.append(offset)
    return offsets

def get_functions():
    functions = []
    for func_ea in utils.Functions():
        # Get function name and demangled name
        func_name = idc.get_func_name(func_ea)
        demangled_name = idc.demangle_name(func_name, api.cvar.inf.long_demnames)
        # Get function bounds
        start, end = get_function_bounds(func_ea)
        # Generate signature
        signature = get_unique_signature(start, end)
        # Get offsets and offset_findall
        offsets = []
        offset_findall = []
        func_disasm = idc.GetDisasm(func_ea)
        lines = func_disasm.split('\n')
        for line in lines:
            if "mov" in line and "rax, [rcx+" in line:
                offset = line.split("[rcx+")[1].split("h")[0]
                offsets.append(offset)
                offset_findall.append(line.strip())
        # Append function information to the list
        functions.append({
            "Address": hex(func_ea),
            "Name": func_name,
            "Demangled": demangled_name,
            "Signature": signature,
            "Offsets": offsets,
            "OffsetFindAll": offset_findall
        })
    return functions

def main():
    # Ask user for the output file path
    path = api.ask_file(True, "*.json", "Output file for dump")
    if not path:
        print("No output file selected.")
        return

    # Get all functions in the IDA database
    all_functions = get_functions()

    # Write the function information to the JSON file
    with open(path, "w") as out:
        json.dump(all_functions, out, indent=4)

    api.msg(f"\nDumped {len(all_functions)} functions to '{path}'")

if __name__ == "__main__":
    main()
