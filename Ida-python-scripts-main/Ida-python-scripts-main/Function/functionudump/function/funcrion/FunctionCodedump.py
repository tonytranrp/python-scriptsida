import idaapi
import idautils
import idc
import ida_hexrays
import ida_kernwin
import ida_bytes
import re
import os
from collections import defaultdict

class CodeAnalyzer:
    def __init__(self):
        self.unknown_symbols = set()
        self.dword_values = {}
        self.complex_types = defaultdict(set)
        self.struct_definitions = {}
        
    def analyze_symbol(self, ea):
        """Analyze a symbol at given address"""
        value = ida_bytes.get_qword(ea) if ea != ida_idaapi.BADADDR else None
        if value is not None:
            self.dword_values[f"dword_{ea:X}"] = value
        return value

    def identify_complex_type(self, type_name):
        """Identify and create struct definition for complex types"""
        if "std::_Tree" in type_name:
            base_type = re.search(r'std::_Tree<(.+?)>', type_name)
            if base_type:
                type_params = base_type.group(1)
                self.complex_types["std::_Tree"].add(type_params)
                return self.generate_tree_struct(type_params)
        return None

    def generate_tree_struct(self, params):
        """Generate a struct definition for std::_Tree"""
        struct_name = f"Tree_{hash(params) & 0xFFFFFFFF:08x}"
        if struct_name not in self.struct_definitions:
            self.struct_definitions[struct_name] = f"""
template<typename T>
struct {struct_name} {{
    T* root;
    size_t size;
    // Additional implementation details
    static T* _Getal(void* ptr) {{ return reinterpret_cast<T*>(ptr); }}
}};"""
        return struct_name

class FunctionDumper:
    def __init__(self, output_file):
        self.output_file = output_file
        self.functions = []
        self.analyzer = CodeAnalyzer()
        self.type_replacements = {
            "LODWORD": "",
            "__int64": "int64_t",
            "__int32": "int32_t",
            "__int16": "int16_t",
            "__int8": "int8_t",
            "unsigned __int64": "uint64_t",
            "unsigned __int32": "uint32_t",
            "unsigned __int16": "uint16_t",
            "unsigned __int8": "uint8_t",
            "__m128": "glm::vec4",
            "__m128i": "glm::ivec4",
            "_OWORD": "std::array<uint8_t, 16>",
            "_QWORD": "uint64_t",
            "_DWORD": "uint32_t",
            "_WORD": "uint16_t",
            "_BYTE": "uint8_t",
            "COERCE_FLOAT": "std::bit_cast<float>",
            "COERCE_UNSIGNED_INT": "static_cast<uint32_t>",
            "_mm_cvtsi128_si32": "_mm_cvtss_f32",
            "FLOAT_1_0": "1.0f",
            "FLOAT_0_5": "0.5f",
            "FLOAT_NaN": "std::numeric_limits<float>::quiet_NaN()",
            "HIDWORD": "static_cast<uint32_t>",
            "FLOAT_N1_0": "-1.0f",
            "FLOAT_N0_5": "-0.5f",
        }

    def parse_function_info(self, line):
        parts = line.strip().split('\t')
        if len(parts) < 3:
            return None
            
        name = parts[0]
        return_type = "float"
        if name.startswith("void"):
            return_type = "void"
            name = name[5:]
            
        func_info = {
            'name': name,
            'return_type': return_type,
            'address': int(parts[2], 16) if parts[2].startswith('0') else None,
            'segment': parts[1] if len(parts) > 1 else None
        }
        return func_info

    def extract_unknown_values(self, code):
        # Find dword references
        dwords = re.findall(r'dword_([0-9A-Fa-f]+)', code)
        for dword in dwords:
            addr = int(dword, 16)
            self.analyzer.analyze_symbol(addr)

        # Find complex types
        complex_types = re.findall(r'std::_Tree<[^>]+>', code)
        for type_name in complex_types:
            self.analyzer.identify_complex_type(type_name)

    def generate_support_code(self):
        code = []
        code.append("""#include <cmath>
#include <algorithm>
#include <cstdint>
#include <array>
#include <limits>
#include <bit>
#include <glm/glm.hpp>
#include <vector>
#include <map>

namespace mce {
    struct Radian {
        float value;
        explicit Radian(float v) : value(v) {}
    };

    struct Degree {
        float value;
        explicit Degree(float v) : value(v) {}
    };
}
""")

        if self.analyzer.dword_values:
            code.append("// Constants")
            for name, value in self.analyzer.dword_values.items():
                code.append(f"static constexpr uint32_t {name} = 0x{value:08X};")
            code.append("")

        if self.analyzer.struct_definitions:
            code.append("// Structure definitions")
            for struct_def in self.analyzer.struct_definitions.values():
                code.append(struct_def)
            code.append("")

        return "\n".join(code)

    def cleanup_variable_declaration(self, line):
        for type_name in re.findall(r'std::_Tree<[^>]+>', line):
            struct_name = self.analyzer.identify_complex_type(type_name)
            if struct_name:
                line = line.replace(type_name, struct_name)
        
        line = re.sub(r'v\d+\s*=\s*0i64', '', line)
        line = re.sub(r'_xmm', '0x7FFFFFFF', line)
        
        for ida_type, cpp_type in self.type_replacements.items():
            if ida_type in line:
                line = line.replace(ida_type, cpp_type)
                
        line = re.sub(r'\[(\d+)\]', r'[{\1}]', line)
        line = re.sub(r'\*(\w+)', r'* \1', line)
        
        # Clean up specific function calls
        line = line.replace('fmaxf(', 'std::max(')
        line = line.replace('fminf(', 'std::min(')
        line = line.replace('fmodf_0(', 'std::fmod(')
        line = line.replace('fsqrt(', 'std::sqrt(')
        
        return line.strip()

    def cleanup_function_body(self, body):
        lines = body.split('\n')
        cleaned_lines = []
        brace_level = 0
        
        for line in lines:
            if not line.strip() or ("=" in line and "0i64" in line):
                continue
                
            self.extract_unknown_values(line)
            line = self.cleanup_variable_declaration(line)
            line = re.sub(r'//.*$', '', line).rstrip()
            
            if '{' in line:
                brace_level += 1
            if '}' in line:
                brace_level -= 1
                
            indent = "  " * brace_level
            if line.strip():
                cleaned_lines.append(indent + line)
                
        return '\n'.join(cleaned_lines)

    def parse_parameters(self, params_str):
        """Parse function parameters into proper C++ format"""
        if not params_str or params_str == "void":
            return "void"
            
        # Handle template parameters
        template_match = re.match(r'(.+?)<(.+?)>\s*\((.*?)\)', params_str)
        if template_match:
            func_name, template_params, params = template_match.groups()
            params = params.split(',')
        else:
            params = params_str.split(',')
            
        formatted_params = []
        for i, param in enumerate(params):
            param = param.strip()
            # Remove redundant const & combinations
            param = re.sub(r'const\s+&\s*$', '', param)
            # Handle const references properly
            if 'const' in param and '&' in param:
                param = re.sub(r'const\s+(\w+)\s*&', r'const \1&', param)
            # Clean up any remaining whitespace
            param = ' '.join(param.split())
            formatted_params.append(f"{param} a{i+1}")
            
        return ', '.join(formatted_params)

    def format_decompiled_code(self, decompiled_text, func_info):
        if not decompiled_text:
            return None
            
        # Extract function signature
        clean_name = func_info['name'].split('(')[0]
        
        # Handle template functions
        template_match = re.match(r'(.+?)<(.+?)>', clean_name)
        if template_match:
            base_name, template_params = template_match.groups()
            template_decl = f"template<typename {', typename '.join(['T'+str(i+1) for i in range(template_params.count(',') + 1)])}>\n"
            func_name = base_name.split('::')[-1]
        else:
            template_decl = ""
            func_name = clean_name.split('::')[-1]
        
        # Parse parameters
        params_match = re.search(r'\((.*?)\)', func_info['name'])
        params = self.parse_parameters(params_match.group(1) if params_match else "void")
        
        # Create function signature
        signature = f"{template_decl}{func_info['return_type']} {func_name}({params})"
        
        # Extract and clean up function body
        body_start = decompiled_text.find('{')
        body_end = decompiled_text.rfind('}')
        if body_start == -1 or body_end == -1:
            return None
            
        body = decompiled_text[body_start:body_end+1]
        cleaned_body = self.cleanup_function_body(body)
        
        return clean_name, f"{signature}\n{cleaned_body}"

    def decompile_function(self, ea):
        try:
            cfunc = ida_hexrays.decompile(ea)
            if cfunc:
                return str(cfunc)
            return None
        except Exception as e:
            print(f"Decompilation error at {hex(ea)}: {str(e)}")
            return None

    def process_function(self, line):
        func_info = self.parse_function_info(line)
        if not func_info or not func_info['address']:
            return

        decompiled = self.decompile_function(func_info['address'])
        if decompiled:
            result = self.format_decompiled_code(decompiled, func_info)
            if result:
                self.functions.append(result)

    def write_output(self):
        namespace_funcs = {}
        
        for clean_name, func_code in self.functions:
            namespace = "::".join(clean_name.split("::")[:-1])
            if namespace not in namespace_funcs:
                namespace_funcs[namespace] = []
            namespace_funcs[namespace].append(func_code)

        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(self.generate_support_code())
            
            for namespace, funcs in sorted(namespace_funcs.items()):
                f.write(f"namespace {namespace} {{\n\n")
                for func in funcs:
                    f.write(func)
                    f.write('\n\n')
                f.write(f"}} // namespace {namespace}\n\n")

    def process_file(self, input_path):
        try:
            with open(input_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                for line in lines[1:]:  # Skip header line
                    self.process_function(line)
            self.write_output()
            print(f"Successfully processed file.")
            print(f"Output written to: {self.output_file}")
        except Exception as e:
            print(f"Error processing file: {str(e)}")

def main():
    input_file = ida_kernwin.ask_file(0, "*.txt", "Select input function list file")
    if not input_file:
        return

    output_file = ida_kernwin.ask_file(1, "*.cpp", "Select output CPP file")
    if not output_file:
        return

    try:
        dumper = FunctionDumper(output_file)
        dumper.process_file(input_file)
        print("Function dumping completed!")
    except Exception as e:
        print(f"Error during execution: {str(e)}")

if __name__ == "__main__":
    main()