import idaapi
import ida_bytes
import idc
import idautils as utils
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
            # Append the signature part to the overall signature
            signature += sig_part + " "
            # Move to the next instruction
            addr += insn.size
        else:
            # If disassembly fails, move to the next byte
            addr += 1
    return signature.strip()

def main():
    # Specify the address for which you want to generate the signature
    address = 0x00000001417D2AD0

    # Get the bounds of the function containing the specified address
    start, end = get_function_bounds(address)
    if start is None or end is None:
        print("Failed to determine the bounds of the containing function.")
        return

    # Generate the unique signature
    signature = get_unique_signature(start, end)

    # Output the signature
    print("Generated Signature:")
    print(signature)

if __name__ == "__main__":
    main()
