#!/bin/bash

# Création de l'arborescence principale
mkdir -p BIC-generator/{core_engine,obfuscation,command_control,anti_analysis,builders,tests,docs}

# Core Engine
mkdir -p BIC-generator/core_engine/{encryption,injection,persistence}
mkdir -p BIC-generator/core_engine/encryption/hybrid
mkdir -p BIC-generator/core_engine/injection/syscalls
mkdir -p BIC-generator/core_engine/persistence/{windows,linux}

# Obfuscation
mkdir -p BIC-generator/obfuscation/{llvm_passes,packers}

# Command & Control
mkdir -p BIC-generator/command_control/{dns_tunneling,tor_embedded,traffic_mimicry}

# Tests
mkdir -p BIC-generator/tests/{virtual_machines,sample_data,logs}
mkdir -p BIC-generator/tests/sample_data/{documents,images}
mkdir -p BIC-generator/tests/logs/screenshots

# Documentation
mkdir -p BIC-generator/docs/{legal,technical,research_paper}

# Création des fichiers
# Encryption
touch BIC-generator/core_engine/encryption/hybrid/aes_256.rs
touch BIC-generator/core_engine/encryption/hybrid/rsa_4096.cpp
touch BIC-generator/core_engine/encryption/hybrid/key_manager.py
touch BIC-generator/core_engine/encryption/file_handler.cpp

# Injection
touch BIC-generator/core_engine/injection/process_injector.cpp
touch BIC-generator/core_engine/injection/syscalls/direct_syscalls.asm
touch BIC-generator/core_engine/injection/reflective_dll_loader.c

# Persistence
touch BIC-generator/core_engine/persistence/windows/registry_hook.cpp
touch BIC-generator/core_engine/persistence/windows/service_hijack.cpp
touch BIC-generator/core_engine/persistence/linux/cron_job.sh

# Obfuscation
touch BIC-generator/obfuscation/llvm_passes/control_flow_flattening.cpp
touch BIC-generator/obfuscation/llvm_passes/string_encryption_pass.cpp
touch BIC-generator/obfuscation/packers/custom_packer.py
touch BIC-generator/obfuscation/string_obfuscator.h

# C&C
touch BIC-generator/command_control/dns_tunneling/dns_exfil.py
touch BIC-generator/command_control/tor_embedded/mini_tor_client.c
touch BIC-generator/command_control/traffic_mimicry/http2_mimic.py

# Anti-analysis
touch BIC-generator/anti_analysis/sandbox_detection.cpp
touch BIC-generator/anti_analysis/debugger_checks.asm
touch BIC-generator/anti_analysis/user_activity_monitor.py

# Builders
touch BIC-generator/builders/windows_builder.py
touch BIC-generator/builders/linux_builder.sh

# Tests
touch BIC-generator/tests/virtual_machines/win10_sanitized.ova
touch BIC-generator/tests/virtual_machines/ubuntu_secure.ova
touch BIC-generator/tests/sample_data/documents/test_doc.docx
touch BIC-generator/tests/sample_data/documents/test_xlsx.xlsx
touch BIC-generator/tests/sample_data/images/sample.jpg
touch BIC-generator/tests/logs/session_20230819.log.enc
touch BIC-generator/tests/logs/screenshots/.keep  # Fichier vide pour conserver le dossier

# Documentation
touch BIC-generator/docs/legal/university_approval.pdf
touch BIC-generator/docs/legal/ethics_commitment.txt
touch BIC-generator/docs/technical/mitre_attack_matrix.md
touch BIC-generator/docs/technical/encryption_schema.pdf
touch BIC-generator/docs/research_paper/thesis_draft.tex

echo "Structure créée avec succès!"
