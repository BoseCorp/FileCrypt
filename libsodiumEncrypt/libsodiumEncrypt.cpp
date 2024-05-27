#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sodium.h"

#define FILENAME "capi_bose2.so"
#define ENCRYPTED_FILENAME "encrypted_file.so"
#define DECRYPTED_FILENAME "decrypted_file.so"
#pragma warning( disable : 4996)

//#define MESSAGE ((const unsigned char *) "test")
#define MESSAGE_LEN 8
#define CIPHERTEXT_LEN (crypto_secretbox_MACBYTES + MESSAGE_LEN)

#include <stdio.h>
#include <sodium.h>

#define CHUNK_SIZE 4096

static int
encrypt(const char* target_file, const char* source_file,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    unsigned char  buf_in[CHUNK_SIZE];
    unsigned char  buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE* fp_t, * fp_s;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    unsigned char  tag;

    fp_s = fopen(source_file, "rb");
    fp_t = fopen(target_file, "wb");
    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
    fwrite(header, 1, sizeof header, fp_t);
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen,
            NULL, 0, tag);
        fwrite(buf_out, 1, (size_t)out_len, fp_t);
    } while (!eof);
    fclose(fp_t);
    fclose(fp_s);
    return 0;
}

static int
decrypt(const char* target_file, const char* source_file,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    unsigned char  buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  buf_out[CHUNK_SIZE];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE* fp_t, * fp_s;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    int            ret = -1;
    unsigned char  tag;

    fp_s = fopen(source_file, "rb");
    fp_t = fopen(target_file, "wb");
    fread(header, 1, sizeof header, fp_s);
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        goto ret; /* incomplete header */
    }
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag,
            buf_in, rlen, NULL, 0) != 0) {
            goto ret; /* corrupted chunk */
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            if (!eof) {
                goto ret; /* end of stream reached before the end of the file */
            }
        }
        else { /* not the final chunk yet */
            if (eof) {
                goto ret; /* end of file reached before the end of the stream */
            }
        }
        fwrite(buf_out, 1, (size_t)out_len, fp_t);
    } while (!eof);

    ret = 0;
ret:
    fclose(fp_t);
    fclose(fp_s);
    return ret;
}

int
main(void)
{
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    int ret = 0;

    ret = sodium_init();
    if (ret != 0) {
        printf("sodium_init fail ret=0x%x\n", ret);
        return 1;
    }
    crypto_secretstream_xchacha20poly1305_keygen(key);
    ret = encrypt(ENCRYPTED_FILENAME, FILENAME, key);
    if (ret != 0) {
        printf("encrypt fail ret=0x%x\n", ret);
        return 1;
    }
    printf("encrypt succeed\n");

    ret = decrypt(DECRYPTED_FILENAME, ENCRYPTED_FILENAME, key);
    if (ret != 0) {
        printf("decrypt fail ret=0x%x\n", ret);
        return 1;
    }
    printf("decrypt succeed\n");

    return 0;
}