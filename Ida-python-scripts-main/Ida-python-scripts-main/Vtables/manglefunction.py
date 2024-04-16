import re

def mangle_function(function_signature):
    # Define regex patterns to match different parts of the function signature
    return_type_pattern = r'(?P<return_type>\w+)(?=\s*::)'
    class_name_pattern = r'(?<=::)(?P<class_name>\w+)'
    function_name_pattern = r'(?P<function_name>\w+)(?=\()'
    parameters_pattern = r'\((?P<parameters>.*)\)'
    
    # Extract different parts of the function signature using regex
    return_type_match = re.search(return_type_pattern, function_signature)
    class_name_match = re.search(class_name_pattern, function_signature)
    function_name_match = re.search(function_name_pattern, function_signature)
    parameters_match = re.search(parameters_pattern, function_signature)
    
    # If any part is missing, return None
    if not (return_type_match and class_name_match and function_name_match and parameters_match):
        return None
    
    # Construct the mangled function name
    mangled_function_name = "?{}@{}@@QEBAAEAV{}@@XZ".format(
        function_name_match.group('function_name'),
        class_name_match.group('class_name'),
        return_type_match.group('return_type')
    )
    
    return mangled_function_name
#?getSupplies@Player@@QEBAAEBVPlayerInventory@@XZ
#?getSupplies@getSupplies@@QEBAAEAVPlayer@@XZ
# Example usage
function_signature = "Player::getSupplies(void)"
mangled_function = mangle_function(function_signature)
print("Mangled function:", mangled_function)
