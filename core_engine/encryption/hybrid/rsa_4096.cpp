#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <memory>
#include <stdexcept>
#include <vector>
#include <sodium.h>
#include <immintrin.h>

class PostQuantumRSA {
public:
    PostQuantumRSA() : rsa(nullptr) {
        if (sodium_init() < 0) {
            throw std::runtime_error("Libsodium initialization failed");
        }
    }

    void generate_keys() {
        // Generate traditional RSA-4096 key
        rsa = RSA_new();
        BIGNUM* bn = BN_new();
        BN_set_word(bn, RSA_F4);
        
        if (!RSA_generate_key_ex(rsa, 4096, bn, nullptr)) {
            BN_free(bn);
            RSA_free(rsa);
            throw std::runtime_error("Failed to generate RSA keys");
        }
        BN_free(bn);

        // Generate post-quantum key pair
        crypto_kem_keypair(pq_public_key, pq_secret_key);
    }

    std::vector<unsigned char> hybrid_encrypt(const std::vector<unsigned char>& plaintext) {
        // Generate random session key
        unsigned char session_key[32];
        randombytes_buf(session_key, sizeof(session_key));

        // Encrypt session key with post-quantum KEM
        unsigned char ciphertext[PQ_CIPHERTEXT_LEN];
        unsigned char ss[PQ_SHARED_SECRET_LEN];
        crypto_kem_enc(ciphertext, ss, pq_public_key);

        // Encrypt plaintext with AES-256-GCM
        unsigned char nonce[12];
        randombytes_buf(nonce, sizeof(nonce));
        
        std::vector<unsigned char> encrypted(plaintext.size() + 16);
        unsigned long long ciphertext_len;
        crypto_aead_aes256gcm_encrypt(
            encrypted.data(), &ciphertext_len,
            plaintext.data(), plaintext.size(),
            nullptr, 0,
            nullptr, nonce, session_key
        );

        // Combine results
        std::vector<unsigned char> result;
        result.reserve(sizeof(ciphertext) + sizeof(nonce) + encrypted.size());
        result.insert(result.end(), ciphertext, ciphertext + sizeof(ciphertext));
        result.insert(result.end(), nonce, nonce + sizeof(nonce));
        result.insert(result.end(), encrypted.begin(), encrypted.end());

        // Securely wipe sensitive data
        sodium_memzero(session_key, sizeof(session_key));
        sodium_memzero(ss, sizeof(ss));

        return result;
    }

    std::vector<unsigned char> hybrid_decrypt(const std::vector<unsigned char>& ciphertext) {
        if (ciphertext.size() < PQ_CIPHERTEXT_LEN + 12) {
            throw std::runtime_error("Invalid ciphertext length");
        }

        // Extract components
        const unsigned char* pq_ciphertext = ciphertext.data();
        const unsigned char* nonce = pq_ciphertext + PQ_CIPHERTEXT_LEN;
        const unsigned char* aes_ciphertext = nonce + 12;
        size_t aes_ciphertext_len = ciphertext.size() - PQ_CIPHERTEXT_LEN - 12;

        // Decrypt post-quantum KEM to get session key
        unsigned char session_key[32];
        unsigned char ss[PQ_SHARED_SECRET_LEN];
        crypto_kem_dec(ss, pq_ciphertext, pq_secret_key);

        // Derive AES key from shared secret
        crypto_generichash(session_key, sizeof(session_key), ss, sizeof(ss), nullptr, 0);

        // Decrypt AES-256-GCM ciphertext
        std::vector<unsigned char> plaintext(aes_ciphertext_len - 16);
        unsigned long long plaintext_len;
        if (crypto_aead_aes256gcm_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr,
            aes_ciphertext, aes_ciphertext_len,
            nullptr, 0,
            nonce, session_key
        ) != 0) {
            throw std::runtime_error("Decryption failed");
        }

        // Securely wipe sensitive data
        sodium_memzero(session_key, sizeof(session_key));
        sodium_memzero(ss, sizeof(ss));

        plaintext.resize(plaintext_len);
        return plaintext;
    }

    ~PostQuantumRSA() {
        if (rsa) {
            RSA_free(rsa);
            rsa = nullptr;
        }
        sodium_memzero(pq_secret_key, sizeof(pq_secret_key));
    }

private:
    static constexpr size_t PQ_PUBLIC_KEY_LEN = crypto_kem_PUBLICKEYBYTES;
    static constexpr size_t PQ_SECRET_KEY_LEN = crypto_kem_SECRETKEYBYTES;
    static constexpr size_t PQ_CIPHERTEXT_LEN = crypto_kem_CIPHERTEXTBYTES;
    static constexpr size_t PQ_SHARED_SECRET_LEN = crypto_kem_BYTES;

    RSA* rsa;
    unsigned char pq_public_key[PQ_PUBLIC_KEY_LEN];
    unsigned char pq_secret_key[PQ_SECRET_KEY_LEN];
};