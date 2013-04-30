
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <paths.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

struct bincert {
    uint8_t magic_cert[4];
    uint8_t version_major[2];
    uint8_t version_minor[2];

    uint8_t server_publickey[crypto_box_PUBLICKEYBYTES];
    uint8_t magic_query[8];
    uint8_t serial[4];
    uint8_t ts_begin[4];
    uint8_t ts_end[4];
    uint8_t end[];
};

typedef struct bincert bincert_t;

struct signed_bincert {
    uint8_t magic_cert[4];
    uint8_t version_major[2];
    uint8_t version_minor[2];

    uint8_t signed_data[];
};

typedef struct signed_bincert signed_bincert_t;

#define DNSCRYPT_MAGIC_QUERY "q6fnvWj8"

#define RESOLVER_PUBLICKEY "\xE0\x7C\x5F\x90\x03\x00\x69\x42\x00\xFC\x9A\x1E" \
    "\x46\x55\x43\x4B\x20\x41\x20\x44\x55\x43\x4B\x4A\xFC\x7A\xBA\x18\x4A\x62" \
    "\x46\x2E"

#define SERVER_SIGN_PUBLICKEY \
    "\xB7\x35\x11\x40\x20\x6F\x22\x5D\x3E\x2B\x00\x69\x42\x00\x69\x1E\xA1\xC3" \
    "\x46\x55\x43\x4B\x20\x41\x20\x44\x55\x43\x4B\x43\xFB\x79"

#define SERVER_SIGN_SECRETKEY "\x46\x55\x43\x4B\x20\x41\x20\x44\x55\x43\x4B" \
"\x46\x55\x43\x4B\x20\x41\x20\x44\x55\x43\x4B\x46\x55\x43\x4B\x20\x41\x20\x44\x55\x43\x4B" \
"\x46\x55\x43\x4B\x20\x41\x20\x44\x55\x43\x4B\x46\x55\x43\x4B\x20\x41\x20\x44\x55\x43\x4B"

static void
dnscrypt_key_to_fingerprint(char fingerprint[80U], const uint8_t * const key)
{
    const size_t fingerprint_size = 80U;
    size_t       fingerprint_pos = (size_t) 0U;
    size_t       key_pos = (size_t) 0U;

    assert(crypto_box_PUBLICKEYBYTES == 32U);
    assert(crypto_box_SECRETKEYBYTES == 32U);
    for (;;) {
        assert(fingerprint_size > fingerprint_pos);
        snprintf(&fingerprint[fingerprint_pos],
                 fingerprint_size - fingerprint_pos, "%02X%02X",
                 key[key_pos], key[key_pos + 1U]);
        key_pos += 2U;
        if (key_pos >= crypto_box_PUBLICKEYBYTES) {
            break;
        }
        fingerprint[fingerprint_pos + 4U] = ':';
        fingerprint_pos += 5U;
    }
}

static int
bincert_display_txt_record_tinydns(const signed_bincert_t *signed_bincert,
                                   const size_t signed_bincert_len)
{
    size_t i = (size_t) 0U;
    int    c;

    fputs("'2.dnscrypt-cert:", stdout);
    while (i < signed_bincert_len) {
        c = (int) *(signed_bincert->magic_cert + i);
        if (isprint(c) && c != ':' && c != '\\' && c != '&' && c != '<' && c != '>') {
            putchar(c);
        } else {
            printf("\\%03o", c);
        }
        i++;
    }
    puts(":86400");

    return 0;
}

static int
bincert_display_txt_record(const signed_bincert_t *signed_bincert,
                           const size_t signed_bincert_len)
{
    size_t i = (size_t) 0U;
    int    c;

    fputs("2.dnscrypt-cert\t86400\tIN\tTXT\t\"", stdout);
    while (i < signed_bincert_len) {
        c = (int) *(signed_bincert->magic_cert + i);
        if (isprint(c) && c != '"' && c != '\\') {
            putchar(c);
        } else {
            printf("\\%03d", c);
        }
        i++;
    }
    puts("\"");

    return 0;
}

static int
bincert_sign(bincert_t * const bincert,
             signed_bincert_t ** const signed_bincert_p,
             size_t * const signed_bincert_len_p)
{
    signed_bincert_t   *signed_bincert;
    size_t              bincert_len;
    size_t              signed_bincert_len;
    size_t              unsigned_data_len;
    unsigned long long  signed_data_len_ul;

    bincert_len = (size_t) (bincert->end - bincert->magic_cert);
    signed_bincert = malloc(bincert_len + crypto_sign_ed25519_BYTES);
    if (signed_bincert == NULL) {
        return -1;
    }
    assert(signed_bincert->signed_data - signed_bincert->magic_cert ==
           bincert->server_publickey - bincert->magic_cert);
    memcpy(signed_bincert, bincert,
           (size_t) (bincert->server_publickey - bincert->magic_cert));
    unsigned_data_len = bincert->end - bincert->server_publickey;
    crypto_sign_ed25519(signed_bincert->signed_data, &signed_data_len_ul,
                (const unsigned char *) bincert->server_publickey,
                (unsigned long long) unsigned_data_len,
                (const unsigned char *) SERVER_SIGN_SECRETKEY);
    signed_bincert_len =
        (size_t) (signed_bincert->signed_data - signed_bincert->magic_cert)
            + (size_t) signed_data_len_ul;
    assert(signed_bincert_len - bincert_len <= crypto_sign_ed25519_BYTES);
    assert(signed_bincert_len < (size_t) 256U);
    *signed_bincert_p = signed_bincert;
    *signed_bincert_len_p = signed_bincert_len;

    return 0;
}

static int
bincert_build(bincert_t * const bincert)
{
    uint8_t server_publickey[crypto_box_PUBLICKEYBYTES];
    uint8_t server_secretkey[crypto_box_SECRETKEYBYTES];
    time_t  now = time(NULL);
    char fingerprint[80U];

    crypto_box_keypair(server_publickey, server_secretkey);
    dnscrypt_key_to_fingerprint(fingerprint, server_secretkey);
    puts("\n* New server secret key for dnscrypt:\n");
    puts(fingerprint);
    *bincert = (bincert_t) {
        .magic_cert = { 'D', 'N', 'S', 'C' },
        .version_major = { 0U, 1U },
        .version_minor = { 0U, 0U }
    };
    (void) sizeof(int[sizeof(RESOLVER_PUBLICKEY) - 1U ==
                      sizeof(bincert->server_publickey) ? 1 : -1]);
    memcpy(bincert->server_publickey, server_publickey,
           sizeof(bincert->server_publickey));

    (void) sizeof(int[sizeof(DNSCRYPT_MAGIC_QUERY) - 1U ==
                      sizeof(bincert->magic_query) ? 1 : -1]);
    memcpy(bincert->magic_query, DNSCRYPT_MAGIC_QUERY,
           sizeof(bincert->magic_query));

    const uint32_t now_u32_n = htonl((uint32_t) now);
    memcpy(bincert->serial, &now_u32_n, sizeof(now_u32_n));

    const uint32_t ts_begin_u32_n = now_u32_n;
    memcpy(bincert->ts_begin, &ts_begin_u32_n, sizeof(ts_begin_u32_n));

    const uint32_t ts_end_u32_n = htonl(now + (uint32_t) 31557600U);
    memcpy(bincert->ts_end, &ts_end_u32_n, sizeof(ts_end_u32_n));

    return 0;
}

static int
bincert_build_and_display(void)
{
    signed_bincert_t *signed_bincert;
    bincert_t         bincert;
    size_t            signed_bincert_len;

    if (bincert_build(&bincert) != 0) {
        return -1;
    }
    if (bincert_sign(&bincert, &signed_bincert, &signed_bincert_len) != 0) {
        return -1;
    }
    char fingerprint[80U];
    puts("\n* Server public key for signing records:\n");
    dnscrypt_key_to_fingerprint(fingerprint,
                                (const uint8_t *) SERVER_SIGN_PUBLICKEY);
    puts(fingerprint);
    puts("\n* Server public key for dnscrypt:\n");
    dnscrypt_key_to_fingerprint(fingerprint, bincert.server_publickey);
    puts(fingerprint);
    puts("\n* Magic byte sequence for queries using this certificate:\n");
    puts(DNSCRYPT_MAGIC_QUERY);
    puts("\n* Record for nsd:\n");
    bincert_display_txt_record(signed_bincert, signed_bincert_len);
    puts("\n* Record for tinydns:\n");
    bincert_display_txt_record_tinydns(signed_bincert, signed_bincert_len);
    free(signed_bincert);

    return 0;
}

int
main(void)
{
    sodium_init();
    if (bincert_build_and_display() != 0) {
        return 1;
    }
    return 0;
}
