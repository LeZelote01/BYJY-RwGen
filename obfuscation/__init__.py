"""
BYJY-RwGen Obfuscation Module
Advanced code obfuscation techniques for cybersecurity research
FOR DEFENSIVE RESEARCH PURPOSES ONLY
"""

from .ControlFlowFlattening import ControlFlowFlattening
from .StringEncryptionPass import StringEncryptionPass
from .StringObfuscator import StringObfuscator
from .packers.custom_packer import CustomPacker

__all__ = [
    'ControlFlowFlattening',
    'StringEncryptionPass', 
    'StringObfuscator',
    'CustomPacker'
]

__version__ = "3.2.1"
__author__ = "BYJY-RwGen Research Team"
__email__ = "security-research@university.edu"
__description__ = "Advanced obfuscation techniques for cybersecurity research"

# Research compliance
RESEARCH_MODE = True
ACADEMIC_USE_ONLY = True

if RESEARCH_MODE:
    print("[+] BYJY-RwGen Obfuscation Module loaded for research purposes")
    print("[!] This module is for defensive cybersecurity research only")