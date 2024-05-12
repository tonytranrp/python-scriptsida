import ida_ida
import ida_idaapi
import ida_name
import ida_bytes
import ida_pro
import ida_auto
import ida_search
import ida_hexrays
import idautils
import idaapi
import ida_nalt
import ida_funcs
import ida_typeinf
import idc
import json
from pathlib import Path
import re
import os

def enhance_signature(signature, target_address):
    enhanced_signatures = []
    sig_parts = signature.split()
    for i in range(len(sig_parts)):
        enhanced_sig = list(sig_parts)
        enhanced_sig[i] = "??"  # Replace each pair of hex digits with "??" one at a time
        enhanced_signature = " ".join(enhanced_sig)
        enhanced_signatures.append(enhanced_signature)
        
        # Search for the enhanced signature and check if it leads to the expected address
        begin_address = MIN_EA
        ea = ida_search.find_binary(begin_address, MAX_EA, enhanced_signature, 0, ida_search.SEARCH_DOWN)
        if ea != idaapi.BADADDR:
            if ea == target_address:
                idaapi.msg(f"Enhanced Signature {i+1}: {enhanced_signature} - Correct\n")
            else:
                idaapi.msg(f"Enhanced Signature {i+1}: {enhanced_signature} - Incorrect\n")
        else:
            idaapi.msg(f"Enhanced Signature {i+1}: {enhanced_signature} - Not found\n")

    return enhanced_signatures


DATABASE_FILE = Path(idc.get_idb_path())
DATABASE_DIRECTORY = DATABASE_FILE.parent
DATABASE_INFO = ida_idaapi.get_inf_structure()
MIN_EA = DATABASE_INFO.min_ea
MAX_EA = DATABASE_INFO.max_ea
def search_for_signature(signature, target_address):
    # Search for the enhanced signature in the database
    for enhanced_sig in signature:
        begin_address = MIN_EA
        ea = ida_search.find_binary(begin_address, MAX_EA, enhanced_sig, 0, ida_search.SEARCH_DOWN)
        if ea != idaapi.BADADDR:
            if ea == target_address:
                return enhanced_sig
            else:
                # If the signature matches but does not lead to the expected address, no need to continue searching
                break
    return None


# Example usage:
expects_address = 0x1418CF390
original_signature = "E8 ?? ?? ?? ?? 48 8B 7C 24 60 4C 8B D0"
enhanced_signatures = enhance_signature(original_signature, expects_address)

# Search for the enhanced signatures and find the best one leading to the expected address
best_signature = search_for_signature(enhanced_signatures, expects_address)

if best_signature:
    idaapi.msg(f"Best enhanced signature leading to the expected address: {best_signature}")
else:
    idaapi.msg("Enhanced signature not found leading to the expected address")

