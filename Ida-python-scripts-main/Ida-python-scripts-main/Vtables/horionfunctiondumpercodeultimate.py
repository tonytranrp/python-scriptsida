import idaapi as api
import idautils as utils
import idc as idc
import ida_bytes
import json
import ida_search
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

def modify_signature(address):
    start, end = get_function_bounds(address)
    if start is None or end is None:
        print("Failed to determine the bounds of the containing function.")
        return

    # Generate the original signature
    original_signature = get_unique_signature(start, end)
   
    modified_signature = original_signature.split()  # Split into bytes
    for i in range(len(modified_signature) - 1):
        # Modify each pair of bytes
        modified_bytes = modified_signature.copy()
        modified_bytes[i] = "??"
        modified_bytes[i + 1] = "??"
        modified_signature_str = " ".join(modified_bytes)

        # Search for the modified signature
        found_address = ida_search.find_binary(start, end, modified_signature_str, 0, ida_search.SEARCH_DOWN)
        if found_address == address:
            # If the modified signature leads to the same address, update the signature
            original_signature = modified_signature_str
        else:
            # If it doesn't match, revert the changes
            modified_bytes[i] = original_signature.split()[i]
            modified_bytes[i + 1] = original_signature.split()[i + 1]
            modified_signature_str = " ".join(modified_bytes)

    

def get_offsets(func_ea):
    offsets = set()  # Using a set to ensure uniqueness
    func_disasm = idc.GetDisasm(func_ea)
    lines = func_disasm.split('\n')
    for line in lines:
        if "mov" in line and "rax, [rcx+" in line:
            offset = line.split("[rcx+")[1].split("h")[0]
            offsets.add(offset)
    return list(offsets)

def get_offsetsall(func_ea):
    offsets = set()  # Using a set to ensure uniqueness
    start, end = get_function_bounds(func_ea)
    for addr in range(start, end):
        line = idc.GetDisasm(addr)
        if "mov" in line and any([reg in line for reg in ["rax, [rcx+", "rbx, [rcx+", "rdx, [rsi+", "ecx, [rax+", "rax, [rax+", "eax, [rsi+","ecx, [rbx+","rcx, [rcx+","rax, [rbx+","rcx, [rbx+", "ebx, [rsi+","rbx, [rax+","rbx, [rax+","rcx, [rdx+","rcx, [rdx+","rdx, [rdx+","rdx, [rdx+","rcx, [rsi+","rax, [rdx+","rbx, [rbx+","rbx, [rbx+","rax, [rsi+","rcx, [rdx+","rcx, [rdx+","rdx, [rdx+","rdx, [rdx+","rcx, [rsi+","rax, [rdx+"]]):
            offset = line.split("[")[1].split("]")[0]
            offsets.add(offset)
    return list(offsets)

def get_functions():
    functions = []
    for func_ea in utils.Functions():
        # Get function name and demangled name
        func_name = idc.get_func_name(func_ea)
        demangled_name = idc.demangle_name(func_name, api.cvar.inf.long_demnames)
        # Get function bounds
        start, end = get_function_bounds(func_ea)
        # Generate signature
        signature = modify_signature(func_ea)
        # Get offsets and offset_findall
        offsets = get_offsets(func_ea)
        offset_findall = get_offsetsall(func_ea)
        # Append function information to the list
        functions.append({
            "Address": hex(func_ea),
            "Name": func_name,
            "Demangled": demangled_name,
            "Signature": signature,
            "Offsets": offsets,
            "OffsetsAll": offset_findall
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
