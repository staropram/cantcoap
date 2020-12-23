#ifndef DTLS_EXAMPLE_H
#define DTLS_EXAMPLE_H
typedef struct dtls_psk_key_t {
  unsigned char *id;     /**< psk identity */
  size_t id_length;      /**< length of psk identity  */
  unsigned char *key;    /**< key data */
  size_t key_length;     /**< length of key */
} dtls_psk_key_t;
#endif
