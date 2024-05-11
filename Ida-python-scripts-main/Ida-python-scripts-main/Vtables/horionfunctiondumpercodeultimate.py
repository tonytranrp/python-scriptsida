import idaapi as api
import idautils as utils
import idc as idc
import ida_bytes
import json
import ida_search
import ida_name as idaname
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
            # Change 00 bytes to ? for better readability (IDA uses ? for unknown bytes aka wildcards)
            sig_part = sig_part.replace("00", "??")
            # Append the signature part to the overall signature
            signature += sig_part + " "
            addr += insn.size
        else:
            # If disassembly fails, move to the next byte
            addr += 1
    return signature.strip()

def get_offsets(func_ea):
    offsets = set()  # Using a set to ensure uniqueness
    func_disasm = idc.GetDisasm(func_ea)
    lines = func_disasm.split('\n')
    for line in lines:
        if "mov" in line and "rax, [rcx+" in line:
            offset = line.split("[rcx+")[1].split("h")[0]
            offsets.add(offset)
    return list(offsets)

def get_disscode(func_ea):
    offsets = set()  # Using a set to ensure uniqueness
    func = api.get_func(func_ea)
    if not func:
        return []

    start = func.start_ea
    end = func.end_ea


    # Iterate over each address in the function's range
    for addr in range(start, end):
        # Get the disassembly of the current instruction
        line = idc.GetDisasm(addr)
        offsets.add(line)

    return list(offsets)

def get_offsetsall(func_ea):
    offsets = set()  # Using a set to ensure uniqueness
    func = api.get_func(func_ea)
    if not func:
        return []

    start = func.start_ea
    end = func.end_ea

    # Assemble a list of interesting instruction patterns
    patterns = [
        "rax, [rcx+",
        "rbx, [rcx+",   "[rcx+",
        "rdx, [rsi+",   "[rsi+",
        "ecx, [rax+",   "[rbx+",
        "rax, [rax+",   "[rax+",
        "eax, [rsi+",   "[rdx+",

        "ecx, [rbx+", "rcx, [rcx+", "rax, [rbx+",
        "rcx, [rbx+", "ebx, [rsi+", "rbx, [rax+",
        "rbx, [rax+", "rcx, [rdx+", "rdx, [rdx+",
        "rcx, [rsi+", "rax, [rdx+", "rbx, [rbx+",
        "rax, [rsi+", "rcx, [rdx+", "rdx, [rdx+",
        "rcx, [rsi+", "rax, [rdx+"
    ]

    # Iterate over each address in the function's range
    for addr in range(start, end):
        # Get the disassembly of the current instruction
        line = idc.GetDisasm(addr)

        # Check if any of the interesting instruction patterns are present in the disassembly
        if any(pattern in line for pattern in patterns):
            # Extract the offset from the instruction
            offset = line.split("[")[1].split("]")[0]
            offsets.add(offset)

    return list(offsets)

def get_functions():
    functions_info = []
    for func_ea in utils.Functions():
        func_info = get_function_info(func_ea)
        functions_info.append(func_info)
    return functions_info

def get_function_info(func_ea):
    # Get function name and demangled name
    func_name = idc.get_func_name(func_ea)
    demangled_name = idc.demangle_name(func_name, api.cvar.inf.long_demnames)
    # Get function bounds
    start, end = get_function_bounds(func_ea)
    # Generate signature
    signature = get_unique_signature(start, end)
    # Get offsets and offset_findall
    offsets = get_offsets(func_ea)
    offset_findall = get_offsetsall(func_ea)
    # Get disassembly
    disassembly = get_disscode(func_ea)
    # Print message for the current function being dumped
    api.msg(f"Dumping function: {demangled_name}\n")
    return {
        "Address": hex(func_ea),
        "Name": func_name,
        "Demangled": demangled_name,
        "Signature": signature,
        "Offsets": offsets,
        "OffsetsAll": offset_findall,
        "Disassembly": disassembly
    }


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
