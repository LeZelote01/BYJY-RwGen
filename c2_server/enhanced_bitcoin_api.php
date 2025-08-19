<?php
/**
 * Enhanced Bitcoin API with Multiple Providers and Fallback
 * Improved reliability for payment verification
 * For defensive cybersecurity research purposes only
 */

class EnhancedBitcoinAPI {
    private $providers = [];
    private $current_provider = 0;
    private $api_keys = [];
    private $cache_duration = 300; // 5 minutes
    private $rate_limit_delay = 1; // 1 second between requests
    private $last_request_time = 0;
    
    public function __construct() {
        $this->initializeProviders();
    }
    
    private function initializeProviders() {
        $this->providers = [
            'blockstream' => [
                'name' => 'Blockstream',
                'base_url' => 'https://blockstream.info/api',
                'rate_limit' => 1,
                'timeout' => 10,
                'requires_key' => false
            ],
            'blockchain_info' => [
                'name' => 'Blockchain.info',
                'base_url' => 'https://blockchain.info',
                'rate_limit' => 1,
                'timeout' => 10,
                'requires_key' => false
            ],
            'blockcypher' => [
                'name' => 'BlockCypher',
                'base_url' => 'https://api.blockcypher.com/v1/btc/main',
                'rate_limit' => 3,
                'timeout' => 15,
                'requires_key' => true
            ]
        ];
        
        // Load API keys from environment or config file
        $this->loadApiKeys();
    }
    
    private function loadApiKeys() {
        // Try to load from environment variables
        $blockcypher_key = getenv('BLOCKCYPHER_API_KEY');
        if ($blockcypher_key) {
            $this->api_keys['blockcypher'] = $blockcypher_key;
        }
        
        // Try to load from config file
        $config_file = __DIR__ . '/bitcoin_api_keys.json';
        if (file_exists($config_file)) {
            $config = json_decode(file_get_contents($config_file), true);
            if ($config && is_array($config)) {
                $this->api_keys = array_merge($this->api_keys, $config);
            }
        }
    }
    
    public function verifyPayment($bitcoin_address, $expected_amount, $max_age_hours = 72) {
        $result = [
            'verified' => false,
            'total_received' => 0,
            'expected_amount' => $expected_amount,
            'transactions' => [],
            'provider_used' => null,
            'cache_hit' => false
        ];
        
        // Check cache first
        $cache_key = "payment_verification_{$bitcoin_address}_{$expected_amount}";
        $cached_result = $this->getCachedResult($cache_key);
        
        if ($cached_result) {
            $cached_result['cache_hit'] = true;
            return $cached_result;
        }
        
        // Try each provider
        $errors = [];
        foreach ($this->providers as $provider_id => $provider_config) {
            try {
                $this->respectRateLimit($provider_config['rate_limit']);
                
                $provider_result = $this->verifyPaymentWithProvider(
                    $provider_id, 
                    $bitcoin_address, 
                    $expected_amount, 
                    $max_age_hours
                );
                
                if ($provider_result) {
                    $result = array_merge($result, $provider_result);
                    $result['provider_used'] = $provider_config['name'];
                    
                    // Cache successful result
                    $this->cacheResult($cache_key, $result);
                    
                    return $result;
                }
                
            } catch (Exception $e) {
                $errors[$provider_id] = $e->getMessage();
                error_log("Bitcoin API provider {$provider_id} failed: " . $e->getMessage());
                continue;
            }
        }
        
        // All providers failed
        $result['errors'] = $errors;
        return $result;
    }
    
    private function verifyPaymentWithProvider($provider_id, $bitcoin_address, $expected_amount, $max_age_hours) {
        switch ($provider_id) {
            case 'blockstream':
                return $this->verifyWithBlockstream($bitcoin_address, $expected_amount, $max_age_hours);
                
            case 'blockchain_info':
                return $this->verifyWithBlockchainInfo($bitcoin_address, $expected_amount, $max_age_hours);
                
            case 'blockcypher':
                if (!isset($this->api_keys['blockcypher'])) {
                    throw new Exception("BlockCypher API key not configured");
                }
                return $this->verifyWithBlockCypher($bitcoin_address, $expected_amount, $max_age_hours);
                
            default:
                throw new Exception("Unknown provider: $provider_id");
        }
    }
    
    private function verifyWithBlockstream($bitcoin_address, $expected_amount, $max_age_hours) {
        $url = "https://blockstream.info/api/address/$bitcoin_address";
        
        $response = $this->makeHttpRequest($url);
        $data = json_decode($response, true);
        
        if (!$data) {
            throw new Exception("Invalid response from Blockstream API");
        }
        
        $total_received = $data['chain_stats']['funded_txo_sum'] / 100000000; // Convert from satoshis
        
        if ($total_received >= $expected_amount) {
            // Get recent transactions to verify timing
            $tx_url = "https://blockstream.info/api/address/$bitcoin_address/txs";
            $tx_response = $this->makeHttpRequest($tx_url);
            $transactions = json_decode($tx_response, true);
            
            if (!$transactions) {
                throw new Exception("Failed to get transaction history");
            }
            
            $recent_transactions = $this->filterRecentTransactions($transactions, $max_age_hours);
            
            return [
                'verified' => !empty($recent_transactions),
                'total_received' => $total_received,
                'transactions' => $recent_transactions
            ];
        }
        
        return [
            'verified' => false,
            'total_received' => $total_received,
            'transactions' => []
        ];
    }
    
    private function verifyWithBlockchainInfo($bitcoin_address, $expected_amount, $max_age_hours) {
        $url = "https://blockchain.info/rawaddr/$bitcoin_address?format=json";
        
        $response = $this->makeHttpRequest($url);
        $data = json_decode($response, true);
        
        if (!$data) {
            throw new Exception("Invalid response from Blockchain.info API");
        }
        
        $total_received = $data['total_received'] / 100000000; // Convert from satoshis
        
        if ($total_received >= $expected_amount) {
            $recent_transactions = $this->filterRecentTransactions($data['txs'], $max_age_hours);
            
            return [
                'verified' => !empty($recent_transactions),
                'total_received' => $total_received,
                'transactions' => $recent_transactions
            ];
        }
        
        return [
            'verified' => false,
            'total_received' => $total_received,
            'transactions' => []
        ];
    }
    
    private function verifyWithBlockCypher($bitcoin_address, $expected_amount, $max_age_hours) {
        $api_key = $this->api_keys['blockcypher'];
        $url = "https://api.blockcypher.com/v1/btc/main/addrs/$bitcoin_address?token=$api_key";
        
        $response = $this->makeHttpRequest($url);
        $data = json_decode($response, true);
        
        if (!$data) {
            throw new Exception("Invalid response from BlockCypher API");
        }
        
        $total_received = $data['total_received'] / 100000000; // Convert from satoshis
        
        if ($total_received >= $expected_amount) {
            // Get full transaction details
            $tx_url = "https://api.blockcypher.com/v1/btc/main/addrs/$bitcoin_address/full?token=$api_key";
            $tx_response = $this->makeHttpRequest($tx_url);
            $tx_data = json_decode($tx_response, true);
            
            if (!$tx_data || !isset($tx_data['txs'])) {
                throw new Exception("Failed to get transaction history from BlockCypher");
            }
            
            $recent_transactions = $this->filterRecentTransactions($tx_data['txs'], $max_age_hours);
            
            return [
                'verified' => !empty($recent_transactions),
                'total_received' => $total_received,
                'transactions' => $recent_transactions
            ];
        }
        
        return [
            'verified' => false,
            'total_received' => $total_received,
            'transactions' => []
        ];
    }
    
    private function filterRecentTransactions($transactions, $max_age_hours) {
        $cutoff_time = time() - ($max_age_hours * 3600);
        $recent_transactions = [];
        
        foreach ($transactions as $tx) {
            $tx_time = isset($tx['time']) ? $tx['time'] : 
                      (isset($tx['received']) ? strtotime($tx['received']) : 
                      (isset($tx['block_time']) ? $tx['block_time'] : time()));
            
            if ($tx_time >= $cutoff_time) {
                $recent_transactions[] = [
                    'txid' => $tx['hash'] ?? $tx['txid'] ?? 'unknown',
                    'time' => $tx_time,
                    'confirmations' => $tx['confirmations'] ?? 0,
                    'block_height' => $tx['block_height'] ?? null
                ];
            }
        }
        
        return $recent_transactions;
    }
    
    public function getCurrentBTCRate($currency = 'USD') {
        $cache_key = "btc_rate_$currency";
        $cached_rate = $this->getCachedResult($cache_key);
        
        if ($cached_rate) {
            return $cached_rate;
        }
        
        try {
            // Try CoinGecko first (no API key required)
            $url = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=" . strtolower($currency);
            $response = $this->makeHttpRequest($url);
            $data = json_decode($response, true);
            
            if ($data && isset($data['bitcoin'][strtolower($currency)])) {
                $rate = $data['bitcoin'][strtolower($currency)];
                $this->cacheResult($cache_key, $rate);
                return $rate;
            }
            
        } catch (Exception $e) {
            error_log("Failed to get BTC rate from CoinGecko: " . $e->getMessage());
        }
        
        // Fallback to CoinDesk
        try {
            $url = "https://api.coindesk.com/v1/bpi/currentprice/$currency.json";
            $response = $this->makeHttpRequest($url);
            $data = json_decode($response, true);
            
            if ($data && isset($data['bpi'][$currency]['rate_float'])) {
                $rate = $data['bpi'][$currency]['rate_float'];
                $this->cacheResult($cache_key, $rate);
                return $rate;
            }
            
        } catch (Exception $e) {
            error_log("Failed to get BTC rate from CoinDesk: " . $e->getMessage());
        }
        
        // Return fallback rate if all APIs fail
        return $currency === 'USD' ? 30000 : 25000; // Reasonable fallback values
    }
    
    private function makeHttpRequest($url, $timeout = 10) {
        $ch = curl_init();
        
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_USERAGENT => 'BYJY-RwGen Research Tool/1.0',
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2
        ]);
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        
        curl_close($ch);
        
        if ($response === false || !empty($error)) {
            throw new Exception("HTTP request failed: $error");
        }
        
        if ($http_code >= 400) {
            throw new Exception("HTTP error $http_code for URL: $url");
        }
        
        return $response;
    }
    
    private function respectRateLimit($delay) {
        $time_since_last = time() - $this->last_request_time;
        
        if ($time_since_last < $delay) {
            sleep($delay - $time_since_last);
        }
        
        $this->last_request_time = time();
    }
    
    private function getCachedResult($cache_key) {
        $cache_file = "/tmp/bitcoin_api_cache_" . md5($cache_key) . ".json";
        
        if (file_exists($cache_file)) {
            $cache_data = json_decode(file_get_contents($cache_file), true);
            
            if ($cache_data && $cache_data['expires'] > time()) {
                return $cache_data['data'];
            }
            
            // Cache expired, remove file
            unlink($cache_file);
        }
        
        return null;
    }
    
    private function cacheResult($cache_key, $data) {
        $cache_file = "/tmp/bitcoin_api_cache_" . md5($cache_key) . ".json";
        
        $cache_data = [
            'data' => $data,
            'expires' => time() + $this->cache_duration,
            'created' => time()
        ];
        
        file_put_contents($cache_file, json_encode($cache_data));
    }
    
    public function getProviderStatus() {
        $status = [];
        
        foreach ($this->providers as $provider_id => $provider_config) {
            $provider_status = [
                'name' => $provider_config['name'],
                'available' => false,
                'response_time' => null,
                'last_error' => null
            ];
            
            try {
                $start_time = microtime(true);
                
                // Test with a known Bitcoin address
                $test_address = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'; // Genesis block address
                
                switch ($provider_id) {
                    case 'blockstream':
                        $this->makeHttpRequest("https://blockstream.info/api/address/$test_address", 5);
                        break;
                        
                    case 'blockchain_info':
                        $this->makeHttpRequest("https://blockchain.info/rawaddr/$test_address?format=json&limit=1", 5);
                        break;
                        
                    case 'blockcypher':
                        if (isset($this->api_keys['blockcypher'])) {
                            $key = $this->api_keys['blockcypher'];
                            $this->makeHttpRequest("https://api.blockcypher.com/v1/btc/main/addrs/$test_address?token=$key", 5);
                        } else {
                            throw new Exception("API key not configured");
                        }
                        break;
                }
                
                $provider_status['available'] = true;
                $provider_status['response_time'] = round((microtime(true) - $start_time) * 1000, 2);
                
            } catch (Exception $e) {
                $provider_status['last_error'] = $e->getMessage();
            }
            
            $status[$provider_id] = $provider_status;
        }
        
        return $status;
    }
    
    public function generateBitcoinAddress() {
        // For research purposes, generate a test address
        // In production, this would use proper key generation
        $random_bytes = random_bytes(20);
        $hash160 = hash('ripemd160', hash('sha256', $random_bytes, true), true);
        
        // Add version byte (0x00 for mainnet)
        $versioned_hash = "\x00" . $hash160;
        
        // Calculate checksum
        $checksum = substr(hash('sha256', hash('sha256', $versioned_hash, true), true), 0, 4);
        
        // Create full address
        $full_address = $versioned_hash . $checksum;
        
        // Base58 encode
        return $this->base58Encode($full_address);
    }
    
    private function base58Encode($data) {
        $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        $base = strlen($alphabet);
        $encoded = '';
        
        $num = gmp_init(bin2hex($data), 16);
        
        while (gmp_cmp($num, 0) > 0) {
            list($num, $remainder) = gmp_div_qr($num, $base);
            $encoded = $alphabet[gmp_intval($remainder)] . $encoded;
        }
        
        // Add leading zeros
        for ($i = 0; $i < strlen($data) && ord($data[$i]) === 0; $i++) {
            $encoded = $alphabet[0] . $encoded;
        }
        
        return $encoded;
    }
}

// Backward compatibility alias
class BitcoinAPI extends EnhancedBitcoinAPI {
    // This class maintains backward compatibility with existing code
}
?>