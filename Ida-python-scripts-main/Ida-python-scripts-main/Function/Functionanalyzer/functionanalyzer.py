import idaapi
import ida_hexrays
import ida_funcs
import ida_name
import ida_xref
import idc
import ida_bytes
import re
import json

class FunctionAnalyzer:
    def __init__(self, func_ea=None):
        """
        Initialize the Function Analyzer
        
        :param func_ea: Address of the function to analyze (current function if None)
        """
        # Use current function if no address provided
        self.func_ea = func_ea if func_ea is not None else idc.get_func_ea(idc.get_screen_ea())
        
        # Ensure we have a valid function
        if not ida_funcs.get_func(self.func_ea):
            raise ValueError("Invalid function address")
        
        # Function details
        self.func = ida_funcs.get_func(self.func_ea)
        self.func_name = idc.get_func_name(self.func_ea)
        
        # Analysis results
        self.indirect_calls = []
        self.vtable_references = []
        self.memory_accesses = []
        self.potential_callbacks = []

    def analyze_indirect_calls(self):
        """
        Analyze indirect function calls within the function
        """
        # Decompile the function
        try:
            cfunc = ida_hexrays.decompile(self.func_ea)
        except Exception as e:
            print(f"Decompilation error: {e}")
            return []

        # Extract text representation
        cfunc_text = str(cfunc)

        # Regex patterns for indirect calls
        indirect_call_patterns = [
            # Pattern to match function pointer calls like (*(_QWORD *)(...))
            r'\(\*\(.*?\(\w+\s*\+\s*(\d+)i?64\)\)\)\(',
            # Pattern to match vtable-like calls
            r'\(\*\(.*?\[(\d+)\]\)\)\('
        ]

        # Find indirect calls
        indirect_calls = []
        for pattern in indirect_call_patterns:
            matches = re.findall(pattern, cfunc_text)
            for match in matches:
                offset = int(match, 0)
                # Try to find potential function/vtable reference
                try:
                    # Check if the offset leads to a valid function reference
                    potential_funcs = self._find_potential_functions_at_offset(offset)
                    indirect_calls.append({
                        'offset': offset,
                        'potential_functions': potential_funcs
                    })
                except Exception as e:
                    print(f"Error analyzing indirect call at offset {offset}: {e}")

        self.indirect_calls = indirect_calls
        return indirect_calls

    def _find_potential_functions_at_offset(self, offset):
        """
        Find potential functions referenced at a specific offset
        
        :param offset: Offset to investigate
        :return: List of potential function details
        """
        potential_funcs = []
        
        # Iterate through function chunks to find references
        for chunk in idautils.Chunks(self.func_ea):
            # Search for cross-references
            xrefs = list(idautils.CodeRefsFrom(chunk[0], False))
            
            for xref in xrefs:
                try:
                    # Check if xref leads to a function
                    func = ida_funcs.get_func(xref)
                    if func:
                        potential_funcs.append({
                            'address': xref,
                            'name': idc.get_func_name(xref)
                        })
                except Exception:
                    pass

        return potential_funcs

    def analyze_vtable_references(self):
        """
        Identify potential vtable references in the function
        """
        vtable_refs = []
        
        # Decompile the function
        try:
            cfunc = ida_hexrays.decompile(self.func_ea)
        except Exception as e:
            print(f"Decompilation error: {e}")
            return []

        # Extract text representation
        cfunc_text = str(cfunc)

        # Patterns to identify vtable-like references
        vtable_patterns = [
            r'\*\(\w+\s*\+\s*(\d+)i?64\)',  # Offset-based vtable access
            r'\*\(\w+\s*\[(\d+)\]\)'         # Array-like vtable access
        ]

        for pattern in vtable_patterns:
            matches = re.findall(pattern, cfunc_text)
            for match in matches:
                offset = int(match, 0)
                try:
                    # Try to find references or potential class/struct info
                    vtable_info = self._investigate_vtable_reference(offset)
                    if vtable_info:
                        vtable_refs.append(vtable_info)
                except Exception as e:
                    print(f"Error analyzing vtable reference at offset {offset}: {e}")

        self.vtable_references = vtable_refs
        return vtable_refs

    def _investigate_vtable_reference(self, offset):
        """
        Investigate a potential vtable reference
        
        :param offset: Offset to investigate
        :return: Dictionary with vtable reference details
        """
        # Find potential function or structure references
        potential_funcs = []
        potential_structures = []

        # Basic information gathering
        return {
            'offset': offset,
            'potential_functions': potential_funcs,
            'potential_structures': potential_structures
        }

    def generate_report(self):
        """
        Generate a comprehensive report of function analysis
        
        :return: Dictionary containing analysis results
        """
        # Analyze function
        self.analyze_indirect_calls()
        self.analyze_vtable_references()

        return {
            'function_name': self.func_name,
            'function_address': hex(self.func_ea),
            'indirect_calls': self.indirect_calls,
            'vtable_references': self.vtable_references
        }

def show_function_analysis_dialog():
    """
    Show a dialog to analyze the current or selected function
    """
    # Get current function address
    current_func_ea = idc.get_func_ea(idc.get_screen_ea())
    
    if current_func_ea == ida_idaapi.BADADDR:
        ida_kernwin.warning("No function selected!")
        return

    try:
        # Create analyzer
        analyzer = FunctionAnalyzer(current_func_ea)
        
        # Generate report
        report = analyzer.generate_report()
        
        # Create a dialog to display results
        class FunctionAnalysisDialog(ida_kernwin.Form):
            def __init__(self, report):
                ida_kernwin.Form.__init__(self, r"""BUTTON YES NONE
BUTTON NO NONE
BUTTON CANCEL NONE
Function Analysis Results

{FormChangeCb}
<Indirect Calls:{iCalls}>
<VTable References:{iVTables}>
""", {
                    'iCalls': ida_kernwin.Form.MultiLineTextControl(text=json.dumps(report['indirect_calls'], indent=2)),
                    'iVTables': ida_kernwin.Form.MultiLineTextControl(text=json.dumps(report['vtable_references'], indent=2)),
                })
                self.Compiled()

            def OnFormChange(self, fid):
                return 1

        # Create and show dialog
        f = FunctionAnalysisDialog(report)
        f.Execute()
        f.Free()

    except Exception as e:
        ida_kernwin.warning(f"Error analyzing function: {str(e)}")

def register_function_analyzer_menu():
    """
    Register a menu item for function analysis
    """
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            'function_analyzer:analyze',
            'Analyze Function',
            ida_kernwin.action_handler_t(),
            None
        )
    )
    ida_kernwin.attach_action_to_menu(
        'Plugins/',
        'function_analyzer:analyze',
        ida_kernwin.SETMENU_APP
    )

# Attach the functionality to a menu item
if __name__ == '__main__':
    register_function_analyzer_menu()
    show_function_analysis_dialog()