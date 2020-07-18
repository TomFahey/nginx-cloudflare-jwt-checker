#ifndef _NGX_HTTP_JWT_CF_JWK_DECODE_H
#define _NGX_HTTP_JWT_CF_JWK_DECODE_H

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include "ngx_http_jwt_cf_jwk_request.h"

char *base64_urlsafe_to_standard(ngx_pool_t *pool, char* base64url);
unsigned char *base64_decode(ngx_pool_t *pool, u_char* base64data, int* len);
BIGNUM *bignum_base64_decode(ngx_pool_t *pool, u_char* base64bignum, int* len);
u_char *jwk_to_pem_u_char(ngx_pool_t *pool, struct pubkey_t pubkey);

#endif /* _NGX_HTTP_JWT_CF_JWK_DECODE_H */
