import idaapi as api
import idautils as utils
import ida_name as idaname
import idc as idc
import json

def clean_name(name):
    # Remove any ` or ' characters from the name
    return name.replace('`', '').replace("'", '')
def clean_namevftable(name):
    # Remove any ` or ' characters from the name
    return name.replace('const', '').replace("const", '')

def dump_vtables(path):
    # Get all symbol names
    names = dict(utils.Names())

    # Iterate through all symbols
    for address, name in names.items():
        # Demangle the name to check if it's a vftable
        demangled_name = idc.demangle_name(name, api.cvar.inf.long_demnames)
        if demangled_name and "vftable" in demangled_name:
            # Find the nearest name
            nearest_name = idaname.NearestName(names)
            _, n, pos = nearest_name.find(address)

            # Calculate start and finish addresses
            if pos > 0:
                start = list(names.keys())[pos - 1]
                finish = address
            else:
                start = address
                finish = list(names.keys())[pos + 1]

            # Clean up the class name
            n = clean_name(n)
            class_name = clean_namevftable(clean_name(idc.demangle_name(n, api.cvar.inf.long_demnames)))
            
            # Create the vtable header
            header = f"class {class_name} {{ /* address={hex(start)} */\n"
            public_functions = []
            private_functions = []
            protected_functions = []

            # Iterate through vtable entries
            current_address = start
            while current_address < finish:
                function_name = idc.demangle_name(idc.get_func_name(idc.get_qword(current_address)), api.cvar.inf.long_demnames)
                if function_name:
                    # Clean up the function name
                    function_name = clean_name(function_name)

                    # Determine if it's public, private, or protected
                    if 'private:' in function_name:
                        private_functions.append(function_name.replace('private: ', ''))
                    elif 'protected:' in function_name:
                        protected_functions.append(function_name.replace('protected: ', ''))
                    else:
                        public_functions.append(function_name.replace('public: ', ''))
                current_address += 8

            # Add public functions
            if public_functions:
                header += "public:\n"
                for func in public_functions:
                    header += f"\t {func};\n"

            # Add protected functions
            if protected_functions:
                header += "protected:\n"
                for func in protected_functions:
                    header += f"\t {func};\n"

            # Add private functions
            if private_functions:
                header += "private:\n"
                for func in private_functions:
                    header += f"\t {func};\n"

            # Close the class
            header += "};\n\n"

            # Write the vtable header to the output file
            with open(path, "a") as out:
                out.write(header)

    # Notify completion
    api.msg("All vtables dumped successfully")

path = api.ask_file(True, "*.cpp", "Output file for dump")
dump_vtables(path)
