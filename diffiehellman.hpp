#pragma once
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment (lib, "crypt32")

namespace sdk::encryption {
	class diffiehellman {
	private:
		EVP_PKEY_CTX* m_ctx_params = NULL;
		EVP_PKEY_CTX* m_ctx_keygen = NULL;
		EVP_PKEY_CTX* m_ctx_derive = NULL;
		EVP_PKEY* m_privkey = NULL;
		EVP_PKEY* m_peerkey = NULL;
		EVP_PKEY* m_params = NULL;
	public:
		size_t m_curve_id = -1;

		char* m_pub = nullptr;
		size_t m_pub_len = -1;
		unsigned char* m_shared = nullptr;
		size_t m_shared_len = -1;
		diffiehellman(size_t curve_id = NID_sect571r1) { m_curve_id = curve_id; }

		~diffiehellman() {
			if (m_ctx_params != NULL) { EVP_PKEY_CTX_free(m_ctx_params); }
			if (m_ctx_keygen != NULL) { EVP_PKEY_CTX_free(m_ctx_keygen); }
			if (m_ctx_derive != NULL) { EVP_PKEY_CTX_free(m_ctx_derive); }

			if (m_privkey != NULL) { EVP_PKEY_free(m_privkey); }
			if (m_peerkey != NULL) { EVP_PKEY_free(m_peerkey); }
			if (m_params != NULL) { EVP_PKEY_free(m_params); }

			if (m_pub != NULL) { m_pub[0] = '\0'; free(m_pub); }
			if (m_shared != NULL) { m_shared[0] = '\0'; free(m_shared); }
		}

		int derive_pub() {
			if (NULL == (m_ctx_params = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) { return -1; }

			if (1 != EVP_PKEY_paramgen_init(m_ctx_params)) { return -1; }

			if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(m_ctx_params, m_curve_id)) { return -1; }

			if (!EVP_PKEY_paramgen(m_ctx_params, &m_params)) { return -1; }

			if (NULL == (m_ctx_keygen = EVP_PKEY_CTX_new(m_params, NULL))) { return -1; }

			if (1 != EVP_PKEY_keygen_init(m_ctx_keygen)) { return -1; }

			if (1 != EVP_PKEY_keygen(m_ctx_keygen, &m_privkey)) { return -1; }

			BIO* bp = BIO_new(BIO_s_mem());

			if (1 != PEM_write_bio_PUBKEY(bp, m_privkey)) { return -1; }

			BUF_MEM* bptr;
			BIO_get_mem_ptr(bp, &bptr);

			m_pub = (char*)calloc(1, bptr->length);
			if (m_pub == NULL) { BIO_free(bp); return -1; }

			memcpy(m_pub, bptr->data, bptr->length);

			m_pub_len = bptr->length;
			BIO_free(bp);
			return 0;
		}

		int derive_shared(char* peer_key, size_t peer_key_len) {
			BUF_MEM* bptr = BUF_MEM_new();
			BUF_MEM_grow(bptr, peer_key_len);
			BIO* bp = BIO_new(BIO_s_mem());

			memcpy(bptr->data, peer_key, peer_key_len);

			BIO_set_mem_buf(bp, bptr, BIO_NOCLOSE);

			m_peerkey = PEM_read_bio_PUBKEY(bp, NULL, NULL, NULL);

			BIO_free(bp);
			BUF_MEM_free(bptr);

			if (NULL == (m_ctx_derive = EVP_PKEY_CTX_new(m_privkey, NULL))) { return -1; }

			if (1 != EVP_PKEY_derive_init(m_ctx_derive)) { return -1; }

			if (1 != EVP_PKEY_derive_set_peer(m_ctx_derive, m_peerkey)) { return -1; }

			if (1 != EVP_PKEY_derive(m_ctx_derive, NULL, &m_shared_len)) { return -1; }

			if (NULL == (m_shared = (unsigned char*)OPENSSL_malloc(m_shared_len))) { return -1; }

			if (1 != (EVP_PKEY_derive(m_ctx_derive, m_shared, &m_shared_len))) { return -1; }
			return 0;
		}
	};
}
