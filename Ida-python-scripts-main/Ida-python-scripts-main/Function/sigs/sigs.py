import idaapi
import ida_search
import ida_bytes
import ida_kernwin
import idc
import re
import json
import os
import time

class SignatureOptimizer:
    def __init__(self, verbose=True, debug=True):
        self.database_info = idaapi.get_inf_structure()
        self.min_ea = self.database_info.min_ea
        self.max_ea = self.database_info.max_ea
        
        # Simple caching mechanism
        self.pattern_cache = {}
        
        self.verbose = verbose
        self.debug = debug
        
        # Regex for parsing signatures
        self.byte_pattern_regex = re.compile(r'[?]{1,2}|\b[0-9A-Fa-f]{2}\b')
        
        # Common patterns for optimization
        self.common_patterns = [
            ([0xE8, None, None, None, None], 'call_rel32'),
            ([0xE9, None, None, None, None], 'jmp_rel32'),
            ([0x48, 0x8D], 'lea'),
            ([0x48, 0x89], 'mov_reg'),
            ([0x48, 0x8B], 'mov'),
            ([0xFF, 0x15], 'call_indirect')
        ]

    def debug_log(self, message, level='INFO'):
        """Debug logging with timestamp"""
        if self.debug:
            timestamp = time.time()
            print(f"[{timestamp:.4f}] [{level}] {message}")

    def string_to_bytes(self, sig_string):
        """Convert signature to bytes with detailed logging"""
        self.debug_log(f"Parsing signature: {sig_string}", 'PARSE')
        
        parsed_bytes = []
        raw_bytes = self.byte_pattern_regex.findall(sig_string)
        
        for byte in raw_bytes:
            if byte in ['??', '?']:
                parsed_bytes.append(byte)
                self.debug_log(f"  Parsed wildcard: {byte}", 'PARSE')
            else:
                parsed_bytes.append(byte)
                self.debug_log(f"  Parsed byte: {byte}", 'PARSE')
        
        self.debug_log(f"Parsed bytes: {parsed_bytes}", 'PARSE')
        return parsed_bytes

    def bytes_to_string(self, bytes_list):
        """Convert bytes list to signature string"""
        return " ".join(str(b) for b in bytes_list)

    def find_matches_fast(self, signature):
        """Find matches for a signature"""
        self.debug_log(f"Searching signature: {signature}", 'SEARCH')
        
        # Check cache first
        if signature in self.pattern_cache:
            self.debug_log(f"Cache hit for signature", 'CACHE')
            return self.pattern_cache[signature]

        # Prepare search pattern
        binary_pattern = signature.replace("??", "?")
        self.debug_log(f"Binary search pattern: {binary_pattern}", 'SEARCH')
        
        matches = []
        ea = self.min_ea
        match_attempts = 0
        
        search_start = time.time()
        
        while ea != ida_idaapi.BADADDR:
            match_attempts += 1
            
            # Perform binary search
            found_ea = ida_search.find_binary(ea, self.max_ea, binary_pattern, 16, ida_search.SEARCH_DOWN)
            
            if found_ea != ida_idaapi.BADADDR:
                matches.append(found_ea)
                self.debug_log(f"Match found at address: {hex(found_ea)}", 'SEARCH')
                ea = found_ea + 1
            else:
                break
        
        search_time = time.time() - search_start
        
        # Search summary
        self.debug_log(f"Search complete:", 'SUMMARY')
        self.debug_log(f"  Total matches: {len(matches)}", 'SUMMARY')
        self.debug_log(f"  Search attempts: {match_attempts}", 'SUMMARY')
        self.debug_log(f"  Total search time: {search_time:.4f}s", 'SUMMARY')
        
        # Cache results
        self.pattern_cache[signature] = matches
        return matches

    def shorten_signature_smart(self, signature, target_ea):
        """Attempt to shorten signature while maintaining match"""
        bytes_list = self.string_to_bytes(signature)
        original_len = len(bytes_list)
        
        # Try removing chunks from the end
        chunk_sizes = [8, 4, 2, 1]
        
        for chunk_size in chunk_sizes:
            while len(bytes_list) > chunk_size:
                # Remove from the end
                test_bytes = bytes_list[:-chunk_size]
                test_sig = self.bytes_to_string(test_bytes)
                
                if self.verify_signature_fast(test_sig, target_ea):
                    bytes_list = test_bytes
                else:
                    break

        final_sig = self.bytes_to_string(bytes_list)
        return final_sig if len(bytes_list) < original_len else signature

    def optimize_wildcards_smart(self, signature, target_ea):
        """Optimize signature wildcards"""
        bytes_list = self.string_to_bytes(signature)
        length = len(bytes_list)
        best_signature = signature

        # Check common patterns
        for pattern, pattern_name in self.common_patterns:
            for i in range(len(bytes_list) - len(pattern) + 1):
                if all(p is None or bytes_list[i + j] == hex(p)[2:].zfill(2) for j, p in enumerate(pattern)):
                    test_bytes = bytes_list.copy()
                    for j in range(len(pattern)):
                        if pattern[j] is None:
                            test_bytes[i + j] = "??"
                    test_sig = self.bytes_to_string(test_bytes)
                    if self.verify_signature_fast(test_sig, target_ea):
                        bytes_list = test_bytes
                        best_signature = test_sig

        # Check byte sequences
        chunk_size = 4
        i = 0
        while i < length - chunk_size + 1:
            test_bytes = bytes_list.copy()
            test_bytes[i:i+chunk_size] = ["??"] * chunk_size
            test_sig = self.bytes_to_string(test_bytes)
            
            if self.verify_signature_fast(test_sig, target_ea):
                bytes_list = test_bytes
                best_signature = test_sig
                i += chunk_size
            else:
                i += 1

        # Individual byte wildcarding
        for i in range(length):
            if bytes_list[i] != "??":
                test_bytes = bytes_list.copy()
                test_bytes[i] = "??"
                test_sig = self.bytes_to_string(test_bytes)
                if self.verify_signature_fast(test_sig, target_ea):
                    bytes_list[i] = "??"
                    best_signature = test_sig

        return best_signature

    def verify_signature_fast(self, signature, target_ea):
        """Verify signature matches exactly one location"""
        matches = self.find_matches_fast(signature)
        return len(matches) == 1 and matches[0] == target_ea

    def optimize_signature(self, original_sig):
        """Comprehensive signature optimization"""
        start_time = time.time()
        self.debug_log("Starting signature optimization", 'OPTIMIZE')
        self.debug_log(f"Original signature: {original_sig}", 'OPTIMIZE')

        # Find matches
        matches = self.find_matches_fast(original_sig)
        
        # Validate matches
        if not matches:
            self.debug_log("No matches found", 'ERROR')
            return None
        
        if len(matches) > 1:
            self.debug_log(f"Multiple matches found: {len(matches)}", 'WARNING')
            return None

        target_ea = matches[0]
        self.debug_log(f"Unique match at address: {hex(target_ea)}", 'OPTIMIZE')

        # Shorten signature
        shortened_sig = self.shorten_signature_smart(original_sig, target_ea)
        self.debug_log(f"Shortened signature: {shortened_sig}", 'SHORTEN')

        # Optimize wildcards
        optimized_sig = self.optimize_wildcards_smart(shortened_sig, target_ea)
        self.debug_log(f"Optimized signature: {optimized_sig}", 'WILDCARD')

        # Verify final signature
        if not self.verify_signature_fast(optimized_sig, target_ea):
            self.debug_log("Final verification failed", 'ERROR')
            return None

        # Get function context
        func = idaapi.get_func(target_ea)
        func_name = idc.get_func_name(target_ea) if func else "Unknown"
        
        total_time = time.time() - start_time
        self.debug_log("Optimization complete", 'SUMMARY')
        self.debug_log(f"Function: {func_name}", 'SUMMARY')

        return {
            "original": original_sig,
            "optimized": optimized_sig,
            "target_address": hex(target_ea),
            "function_name": func_name,
            "optimization_time": total_time
        }

def load_signatures_from_file(file_path):
    """Load signatures from file with names preserved"""
    try:
        with open(file_path, 'r') as f:
            try:
                # Try JSON first
                signatures = json.load(f)
                # Check if it's a dictionary of named signatures
                if isinstance(signatures, dict):
                    return signatures
                # If it's a list, return None
                return None
            except json.JSONDecodeError:
                # Fall back to text parsing
                return None
    except Exception as e:
        print(f"Error reading file: {e}")
        return None

def get_user_input_path(prompt, file_type):
    """Interactive file path selection"""
    while True:
        input_path = ida_kernwin.ask_file(0, file_type, prompt)
        
        if not input_path:
            print("File selection cancelled.")
            return None
        
        if os.path.exists(input_path):
            return input_path
        
        retry = ida_kernwin.askyn(1, "File does not exist. Would you like to try again?")
        if retry != 1:
            return None

def main():
    # Input file selection
    input_path = get_user_input_path("Select input signatures file", "*.json;*.txt")
    if not input_path:
        return

    # Output file selection
    output_path = get_user_input_path("Select output JSON file", "*.json")
    if not output_path:
        return

    # Start timing
    total_start_time = time.time()

    # Load signatures with names
    signatures = load_signatures_from_file(input_path)
    
    if not signatures:
        print("No signatures found in the file. Ensure it's a JSON with named signatures.")
        return

    # Optimize signatures
    optimizer = SignatureOptimizer(verbose=True, debug=True)
    optimized_results = {}
    processed_count = 0
    failed_count = 0

    print(f"🚀 Processing {len(signatures)} signatures...")
    
    # Process each signature sequentially
    for name, sig in signatures.items():
        try:
            if not sig:
                continue

            result = optimizer.optimize_signature(sig)
            
            if result:
                # Store with original name
                optimized_results[name] = result['optimized']
                processed_count += 1
                
                # Write results to file after each successful optimization
                with open(output_path, 'w') as f:
                    json.dump(optimized_results, f, indent=4)
                
                print(f"✅ Processed: {name}")
            else:
                failed_count += 1
                print(f"❌ Failed to process signature: {name}")

        except Exception as e:
            print(f"Error processing signature {name}: {e}")
            failed_count += 1

    # Final summary
    total_time = time.time() - total_start_time
    print("\n📊 Optimization Summary:")
    print(f"Total signatures processed: {len(signatures)}")
    print(f"Successfully optimized: {processed_count}")
    print(f"Failed to optimize: {failed_count}")
    print(f"Total processing time: {total_time:.2f}s")
    print(f"Optimized signatures saved to {output_path}")

if __name__ == "__main__":
    main()