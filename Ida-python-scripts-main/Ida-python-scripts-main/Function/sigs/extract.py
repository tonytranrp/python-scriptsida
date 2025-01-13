import re
import json
import os

def extract_signatures(input_text):
    # Patterns to match different signature formats
    patterns = [
        # OFFSET_PATTERN_DWORD format
        r'OFFSET_PATTERN_DWORD\("(.+?)",\s*"(.+?)"',
        # FUNCTION_PATTERN format
        r'FUNCTION_PATTERN\("(.+?)",\s*"(.+?)"',
        # OFFSET_DIRECT format (though this doesn't have a signature)
        r'OFFSET_DIRECT\("(.+?)"'
    ]

    # Dictionary to store extracted signatures
    signatures = {}

    # Check each pattern
    for pattern in patterns:
        matches = re.findall(pattern, input_text)
        for match in matches:
            # For OFFSET_PATTERN_DWORD and FUNCTION_PATTERN
            if len(match) == 2:
                name, sig = match
                # Clean up the signature (remove comments, extra spaces)
                sig = re.sub(r'//.*', '', sig).strip()
                signatures[name] = sig

    return signatures

def main():
    # HARDCODED input file path - MODIFY THIS LINE
    input_path = r"sigs\file.txt"

    # Validate input file
    if not os.path.exists(input_path):
        print(f"Error: File {input_path} does not exist.")
        return

    # Read input file
    with open(input_path, 'r') as f:
        input_text = f.read()

    # Extract signatures
    results = extract_signatures(input_text)

    # Determine output file path (same directory as input, with .json extension)
    output_path = os.path.splitext(input_path)[0] + '_signatures.json'

    # Save to JSON file
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=4)

    # Print results
    print("\nExtracted Signatures:")
    print(json.dumps(results, indent=4))
    print(f"\nSignatures saved to {output_path}")

if __name__ == "__main__":
    main()