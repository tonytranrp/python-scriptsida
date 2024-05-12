import idaapi as api
import ida_search
import idc as idc
from pathlib import Path

def enhance_signature(signature, target_address):
    enhanced_signatures = []
    signature_counts = []  # To keep track of the counts of '?'
    
    # Check for "00" in the signature and replace them with "??" immediately
    if "00" in signature:
        signature = signature.replace("00", "??")
        api.msg(f"Enhanced Signature (00 replaced): {signature}\n")
    
    for i, part in enumerate(signature.split()):
        enhanced_sig = signature.replace(part, "??")
        ea = ida_search.find_binary(MIN_EA, MAX_EA, enhanced_sig, 0, ida_search.SEARCH_DOWN)
        
        if ea != api.BADADDR and ea == target_address:
            api.msg(f"Enhanced Signature {i+1}: {enhanced_sig} - Correct\n")
            signature_counts.append(enhanced_sig.count("??"))  # Count the occurrences of '?'
        else:
            api.msg(f"Enhanced Signature {i+1}: {enhanced_sig} - Incorrect\n")
            enhanced_sig = signature  # Revert back if not correct
        enhanced_signatures.append(enhanced_sig)
    
    # Find the index of the signature with the highest count of '?'
    best_index = signature_counts.index(max(signature_counts))
    best_signature = enhanced_signatures[best_index]
    
    return best_signature

DATABASE_FILE = Path(idc.get_idb_path())
DATABASE_DIRECTORY = DATABASE_FILE.parent
DATABASE_INFO = api.get_inf_structure()
MIN_EA = DATABASE_INFO.min_ea
MAX_EA = DATABASE_INFO.max_ea

def search_for_signature(signature, target_address):
    # Search for the enhanced signature in the database
    for enhanced_sig in signature:
        ea = ida_search.find_binary(MIN_EA, MAX_EA, enhanced_sig, 0, ida_search.SEARCH_DOWN)
        if ea != api.BADADDR and ea == target_address:
            return enhanced_sig
    return None

# Example usage:
expects_address = 0x1417F0A10
original_signature = "48 89 5C 24 08 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 D9 48 81 EC B0 00 00 00 0F"
enhanced_signature = enhance_signature(original_signature, expects_address)

# Check if the enhanced signature leads to the expected address
best_signature = search_for_signature([enhanced_signature], expects_address)

if best_signature:
    api.msg(f"Best enhanced signature leading to the expected address: {best_signature}")
else:
    api.msg("Enhanced signature not found leading to the expected address")
