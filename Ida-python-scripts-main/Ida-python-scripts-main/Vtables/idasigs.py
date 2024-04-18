import idaapi
import ida_bytes
import idc
import idautils as utils
import ida_search

def get_function_bounds(ea):
    # Get the start and end addresses of the function containing the given address
    func = idaapi.get_func(ea)
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
    print("Original Signature:")
    print(original_signature)

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

    print("Modified Signature:")
    print(original_signature)

def main():
    # Specify the address for which you want to generate and modify the signature
    address = 0x00000001415FED80
    modify_signature(address)

if __name__ == "__main__":
    main()
