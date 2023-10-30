// OPENSSL
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

// MAIN
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define AES_256_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define BUFSIZE 1024

typedef struct _cipher_params_t{
    unsigned char *key;
    unsigned char *iv;
    unsigned int encrypt;
    const EVP_CIPHER *cipher_type;
}cipher_params_t;

void cleanup(cipher_params_t *params, FILE *ifp, FILE *ofp, int rc){
    free(params);
    fclose(ifp);
    fclose(ofp);
    exit(rc);
}

void file_encrypt_decrypt(cipher_params_t *params, FILE *ifp, FILE *ofp){
    int cipher_block_size = EVP_CIPHER_block_size(params->cipher_type);
    unsigned char in_buf[BUFSIZE], out_buf[BUFSIZE + cipher_block_size];

    int num_bytes_read, out_len;
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL){
        fprintf(stderr, "EVP_CIPHER_CTX_new failed. error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        cleanup(params, ifp, ofp, -4);
    }

    if(!EVP_CipherInit_ex(ctx, params->cipher_type, NULL, NULL, NULL, params->encrypt)){
        fprintf(stderr, "EVP_CipherInit_ex failed. error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        cleanup(params, ifp, ofp, -1);
    }

    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == AES_256_KEY_SIZE);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == AES_BLOCK_SIZE);

    if(!EVP_CipherInit_ex(ctx, NULL, NULL, params->key, params->iv, params->encrypt)){
        fprintf(stderr, "EVP_CipherInit_ex failed. error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
        cleanup(params, ifp, ofp, -1);
    }

    while(1){
        num_bytes_read = fread(in_buf, sizeof(unsigned char), BUFSIZE, ifp);
        if (ferror(ifp)){
            fprintf(stderr, "fread error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(params, ifp, ofp, errno);
        }
        if(!EVP_CipherUpdate(ctx, out_buf, &out_len, in_buf, num_bytes_read)){
            fprintf(stderr, "EVP_CipherUpdate failed. error: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(params, ifp, ofp, -2);
        }
        fwrite(out_buf, sizeof(unsigned char), out_len, ofp);
        if (ferror(ofp)) {
            fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(params, ifp, ofp, errno);
        }
        if (num_bytes_read < BUFSIZE) {
            break;
        }
    }

    if(!EVP_CipherFinal_ex(ctx, out_buf, &out_len)){
        fprintf(stderr, "EVP_CipherFinal_ex failed. error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
        cleanup(params, ifp, ofp, -3);
    }
    fwrite(out_buf, sizeof(unsigned char), out_len, ofp);
    if (ferror(ofp)) {
        fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
        EVP_CIPHER_CTX_cleanup(ctx);
        cleanup(params, ifp, ofp, errno);
    }
    EVP_CIPHER_CTX_cleanup(ctx);
}

int main(int argc, char *argv[]) {
    FILE *f_input, *f_enc, *f_dec;

    if (argc != 2) {
        printf("Use: %s /path/to/file\n", argv[0]);
        return -1;
    }

    cipher_params_t *params = (cipher_params_t *)malloc(sizeof(cipher_params_t));
    if (!params) {
        fprintf(stderr, "ERROR: malloc error: %s\n", strerror(errno));
        return errno;
    }

    unsigned char key[AES_256_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];

    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        fprintf(stderr, "ERROR: RAND_bytes error: %s\n", strerror(errno));
        return errno;
    }
    params->key = key;
    params->iv = iv;

    params->encrypt = 1;

    params->cipher_type = EVP_aes_256_cbc();

	/*
    f_input = fopen(argv[1], "rb");
    if (!f_input) {
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }

    f_enc = fopen("encrypted_file", "wb");
    if (!f_enc) {
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }

    file_encrypt_decrypt(params, f_input, f_enc);

    fclose(f_input);
    fclose(f_enc);
	
	*/

    params->encrypt = 0;

    f_input = fopen(argv[1], "rb");
    if (!f_input) {
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }

    f_dec = fopen("decrypted_file", "wb");
    if (!f_dec) {
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }

    file_encrypt_decrypt(params, f_input, f_dec);

    fclose(f_input);
    fclose(f_dec);

    free(params);

    return 0;
}
