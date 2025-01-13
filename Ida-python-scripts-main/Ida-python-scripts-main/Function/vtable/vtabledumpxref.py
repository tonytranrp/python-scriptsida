import idaapi
import idautils
import idc
import ida_xref
import ida_funcs
import ida_bytes
import ida_name
import re
import json

class VTableDumper:
    def __init__(self, output_file):
        self.output_file = output_file
        self.processed_functions = set()
        self.vtables = {}
        self.classes = set()

    def is_vtable_reference(self, ea):
        """
        Detect if an instruction references a potential vtable
        """
        try:
            # Look for typical vtable-related patterns
            insn = idautils.DecodeInstruction(ea)
            if not insn:
                return False
            
            # Check for common vtable access patterns
            operands = [op for op in insn.ops if op.type == idaapi.o_mem or op.type == idaapi.o_displ]
            
            for op in operands:
                # Look for potential vtable-like naming or memory access
                if op.type == idaapi.o_mem:
                    name = idc.get_name(op.addr)
                    if name and ('vftable' in name.lower() or '_vptr' in name.lower()):
                        return True
                
                # Check displacement for vtable-like patterns
                if op.type == idaapi.o_displ:
                    base_reg = insn.ops[op.n].reg
                    # Often vtables are accessed via base pointer or this pointer
                    if base_reg in [idaapi.R_ESP, idaapi.R_EBP, idaapi.R_RBP, idaapi.R_RSP]:
                        ref_name = idc.get_name(op.addr)
                        if ref_name and ('vftable' in ref_name.lower() or '_vptr' in ref_name.lower()):
                            return True
        except Exception:
            return False
        return False

    def extract_class_name_from_vtable(self, vtable_name):
        """
        Extract class name from vtable symbol
        """
        # Common demangled vtable name patterns
        patterns = [
            r'const\s+(\w+)::\'vftable\'',
            r'(\w+)::\'vftable\'',
            r'vtable\s+for\s+(\w+)',
            r'(\w+)_vftable'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, vtable_name, re.IGNORECASE)
            if match:
                return match.group(1)
        return "UnknownClass"

    def dump_vtable_info(self, vtable_addr):
        """
        Dump detailed information about a vtable
        """
        try:
            vtable_name = idc.get_name(vtable_addr)
            if not vtable_name or 'vftable' not in vtable_name.lower():
                return None
            
            class_name = self.extract_class_name_from_vtable(vtable_name)
            
            # Find vtable size and method count
            methods = []
            current = vtable_addr
            max_methods = 50  # Prevent infinite loop
            
            while max_methods > 0:
                method_addr = idc.get_qword(current)
                if method_addr == 0 or method_addr == idaapi.BADADDR:
                    break
                
                method_name = idc.get_func_name(method_addr)
                if method_name:
                    methods.append(method_name)
                
                current += 8
                max_methods -= 1
            
            return {
                'name': vtable_name,
                'class_name': class_name,
                'methods': methods
            }
        except Exception:
            return None

    def process_function_xrefs(self, func_ea):
        """
        Process cross-references to a function
        """
        if func_ea in self.processed_functions:
            return
        
        self.processed_functions.add(func_ea)
        
        # Get cross-references to this function
        xrefs = list(idautils.CodeRefsTo(func_ea, False))
        
        for xref in xrefs:
            # Try to get the function containing the xref
            xref_func = ida_funcs.get_func(xref)
            if not xref_func:
                continue
            
            # Scan the function for vtable references
            for head in idautils.Heads(xref_func.start_ea, xref_func.end_ea):
                if self.is_vtable_reference(head):
                    vtable_info = self.dump_vtable_info(head)
                    if vtable_info:
                        self.vtables[vtable_info['name']] = vtable_info
                        self.classes.add(vtable_info['class_name'])
                        
                        # Recursively process this function's xrefs
                        self.process_function_xrefs(xref_func.start_ea)

    def generate_cpp_output(self):
        """
        Generate C++ friendly output with classes and vtables
        """
        with open(self.output_file, 'w') as f:
            f.write("// Automatically Generated VTable Analysis\n")
            f.write("#include <cstdint>\n")
            f.write("#include <functional>\n\n")
            
            # Write classes
            f.write("// Classes with VTables\n")
            for class_name in sorted(self.classes):
                f.write(f"class {class_name} {{\n")
                f.write("public:\n")
                
                # Find vtable for this class
                class_vtables = [
                    vtable for vtable in self.vtables.values() 
                    if vtable['class_name'] == class_name
                ]
                
                if class_vtables:
                    f.write("\t// Virtual Function Table Methods\n")
                    for vtable in class_vtables:
                        for method in vtable.get('methods', []):
                            f.write(f"\tvirtual void {method.split('::')[-1]}() = 0;\n")
                
                f.write("};\n\n")
            
            # Detailed vtable information
            f.write("// VTable Detailed Information\n")
            json.dump(
                {name: info for name, info in self.vtables.items()}, 
                f, 
                indent=4
            )

def parse_function_list(function_list):
    """
    Parse the input function list and extract addresses
    """
    function_addresses = []
    
    for line in function_list.split('\n'):
        # Skip empty lines and headers
        line = line.strip()
        if not line or '\t' not in line:
            continue
        
        # Split the line by tabs
        parts = line.split('\t')
        
        # Check if the line has the expected format
        if len(parts) >= 3:
            try:
                # Parse the address (3rd column)
                address = int(parts[2], 16)
                function_addresses.append(address)
            except (ValueError, IndexError):
                print(f"Could not parse address from line: {line}")
    
    return function_addresses

def main():
    # Prompt user to input function list
    function_list = ida_kernwin.ask_text(
        1024, 
        "",
        "Paste Function List (Tab-separated)"
    )
    
    if not function_list:
        print("No function list provided")
        return
    
    # Ask for output file
    output_file = idaapi.ask_file(1, "*.cpp", "Save VTable Analysis")
    
    if not output_file:
        print("No output file selected")
        return
    
    # Parse function addresses
    function_addresses = parse_function_list(function_list)
    
    if not function_addresses:
        print("No valid function addresses found")
        return
    
    # Create VTable Dumper
    dumper = VTableDumper(output_file)
    
    # Process each function address
    for func_addr in function_addresses:
        print(f"Processing function at address: {hex(func_addr)}")
        dumper.process_function_xrefs(func_addr)
    
    # Generate output
    dumper.generate_cpp_output()
    
    print(f"VTable analysis complete. Output saved to {output_file}")

if __name__ == "__main__":
    main()