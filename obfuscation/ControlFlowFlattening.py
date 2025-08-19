#!/usr/bin/env python3
"""
Control Flow Flattening Implementation
Advanced control flow obfuscation for cybersecurity research
FOR DEFENSIVE RESEARCH PURPOSES ONLY
"""

import re
import random
import hashlib
from typing import List, Dict, Tuple


class ControlFlowFlattening:
    """
    Advanced Control Flow Flattening implementation
    Transforms linear code into state-machine-like structures
    """
    
    def __init__(self, complexity_level: str = "medium"):
        self.complexity_level = complexity_level
        self.state_counter = 0
        self.basic_blocks = {}
        self.switch_variable = "state_var"
        
        # Research safety measures
        self.research_mode = True
        self.max_obfuscation_passes = 3 if complexity_level == "low" else 7
        
    def flatten_function(self, source_code: str, function_name: str) -> str:
        """
        Apply control flow flattening to a specific function
        """
        if self.research_mode:
            print(f"[+] Applying CFF to function: {function_name} (Research Mode)")
        
        # Extract function body
        function_pattern = rf'(\w+\s+{re.escape(function_name)}\s*\([^)]*\)\s*\{{)(.*?)(\}})'
        match = re.search(function_pattern, source_code, re.DOTALL)
        
        if not match:
            return source_code
        
        func_signature = match.group(1)
        func_body = match.group(2)
        func_end = match.group(3)
        
        # Parse basic blocks
        basic_blocks = self._extract_basic_blocks(func_body)
        
        if len(basic_blocks) < 2:
            return source_code  # Not worth flattening
        
        # Generate flattened version
        flattened_body = self._generate_flattened_code(basic_blocks)
        
        # Reconstruct function
        flattened_function = func_signature + flattened_body + func_end
        
        # Replace in original source
        return source_code.replace(match.group(0), flattened_function)
    
    def _extract_basic_blocks(self, code: str) -> List[Dict]:
        """
        Extract basic blocks from function body
        """
        blocks = []
        lines = code.strip().split('\n')
        current_block = []
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('//'):
                continue
                
            current_block.append(line)
            
            # Check if this line ends a basic block
            if (line.endswith(';') and 
                ('if' in line or 'while' in line or 'for' in line or 
                 'return' in line or 'break' in line or 'continue' in line)):
                
                blocks.append({
                    'id': len(blocks),
                    'code': current_block.copy(),
                    'next_block': len(blocks) + 1 if len(blocks) < 10 else -1
                })
                current_block = []
        
        # Add remaining code as final block
        if current_block:
            blocks.append({
                'id': len(blocks),
                'code': current_block,
                'next_block': -1  # Terminal block
            })
        
        return blocks
    
    def _generate_flattened_code(self, blocks: List[Dict]) -> str:
        """
        Generate the flattened state machine code
        """
        if not blocks:
            return ""
        
        # Generate state variable and initial setup
        flattened_code = f"""
    // Control Flow Flattening applied - Research Mode
    volatile int {self.switch_variable} = 0;
    
    while (1) {{
        switch ({self.switch_variable}) {{
"""
        
        # Generate cases for each basic block
        for i, block in enumerate(blocks):
            case_code = f"        case {i}:\n"
            case_code += "            {\n"
            
            # Add block code with proper indentation
            for line in block['code']:
                case_code += f"                {line}\n"
            
            # Add state transition
            if block['next_block'] == -1:
                case_code += "                return;\n"  # or appropriate termination
            else:
                # Add some obfuscation to state transitions
                if self.complexity_level == "high":
                    decoy_var = f"decoy_{random.randint(1000, 9999)}"
                    case_code += f"                volatile int {decoy_var} = {random.randint(1, 100)};\n"
                    case_code += f"                {self.switch_variable} = ({decoy_var} > 50) ? {block['next_block']} : {block['next_block']};\n"
                else:
                    case_code += f"                {self.switch_variable} = {block['next_block']};\n"
            
            case_code += "                break;\n"
            case_code += "            }\n"
            
            flattened_code += case_code
        
        # Add default case for robustness
        flattened_code += """        default:
            return; // Unexpected state - research safety
        }
    }
"""
        
        return flattened_code
    
    def add_opaque_predicates(self, code: str) -> str:
        """
        Add opaque predicates to further obfuscate control flow
        """
        if self.complexity_level != "high":
            return code
        
        # Simple opaque predicates that always evaluate to true or false
        opaque_predicates = [
            "((x*x + x) % 2 == 0)",  # Always true for even x, always false for odd x
            "(x*x >= 0)",  # Always true
            "((x*(x+1)) % 2 == 0)",  # Always true
        ]
        
        # Insert opaque predicates before some statements
        lines = code.split('\n')
        obfuscated_lines = []
        
        for line in lines:
            if 'case' in line and ':' in line:
                # Add opaque predicate before case
                pred = random.choice(opaque_predicates).replace('x', str(random.randint(1, 100)))
                obfuscated_lines.append(f"            // Opaque predicate: {pred}")
                obfuscated_lines.append(f"            if ({pred}) {{ /* Always true/false */ }}")
            
            obfuscated_lines.append(line)
        
        return '\n'.join(obfuscated_lines)
    
    def generate_dummy_functions(self, count: int = 3) -> str:
        """
        Generate dummy functions to increase code size and analysis difficulty
        """
        dummy_functions = ""
        
        for i in range(count):
            func_name = f"dummy_func_{i}_{hashlib.md5(str(random.randint(1000, 9999)).encode()).hexdigest()[:8]}"
            
            dummy_functions += f"""
// Dummy function for research obfuscation
static void {func_name}() {{
    volatile int dummy_var = {random.randint(1, 1000)};
    for (int i = 0; i < dummy_var % 10; i++) {{
        dummy_var = (dummy_var * 7) % 997;  // Prime number operations
    }}
    // Research note: This function serves no operational purpose
}}

"""
        
        return dummy_functions
    
    def apply_to_source(self, source_code: str, target_functions: List[str] = None) -> str:
        """
        Apply control flow flattening to entire source file
        """
        if not target_functions:
            # Auto-detect functions to obfuscate
            function_pattern = r'(\w+\s+\w+\s*\([^)]*\)\s*\{)'
            target_functions = re.findall(function_pattern, source_code)
            target_functions = [f.split()[-1].split('(')[0] for f in target_functions]
        
        obfuscated_code = source_code
        
        # Apply flattening to each target function
        for func_name in target_functions:
            if func_name in ['main', 'WinMain']:  # Skip entry points for safety
                continue
                
            obfuscated_code = self.flatten_function(obfuscated_code, func_name)
        
        # Add dummy functions if high complexity
        if self.complexity_level == "high":
            dummy_funcs = self.generate_dummy_functions()
            obfuscated_code = dummy_funcs + obfuscated_code
        
        # Add opaque predicates
        obfuscated_code = self.add_opaque_predicates(obfuscated_code)
        
        return obfuscated_code
    
    def get_statistics(self) -> Dict:
        """
        Get obfuscation statistics for research analysis
        """
        return {
            'complexity_level': self.complexity_level,
            'blocks_processed': len(self.basic_blocks),
            'research_mode': self.research_mode,
            'max_passes': self.max_obfuscation_passes,
            'technique': 'Control Flow Flattening'
        }


# Research testing and validation
def test_control_flow_flattening():
    """
    Test function for research validation
    """
    cff = ControlFlowFlattening("medium")
    
    test_code = """
    int test_function(int x) {
        int result = 0;
        if (x > 0) {
            result = x * 2;
        } else {
            result = x * -1;
        }
        return result;
    }
    """
    
    obfuscated = cff.apply_to_source(test_code, ["test_function"])
    
    print("Original code length:", len(test_code))
    print("Obfuscated code length:", len(obfuscated))
    print("Expansion ratio:", len(obfuscated) / len(test_code))
    
    return obfuscated


if __name__ == "__main__":
    print("BYJY-RwGen Control Flow Flattening - Research Mode")
    print("FOR DEFENSIVE CYBERSECURITY RESEARCH ONLY")
    test_control_flow_flattening()