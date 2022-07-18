/*
 * Copyright (C) 2020 Tom Fahey
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 *
 * https://github.com/TomFahey/nginx-cloudflare-jwt-checker
 */

#include "ngx_http_jwt_cf_jwk_decode.h"

#include <ngx_core.h>

#define PADDING "=========="

extern u_char *base64_urlsafe_to_standard(ngx_pool_t *pool, char* base64url) {
    u_char *b64buffer = ngx_pcalloc(pool, ngx_strlen(base64url)+1);
    ngx_memcpy(b64buffer, base64url, ngx_strlen(base64url));
    u_char a = '-';
    u_char b = '_';
    u_char *p = (u_char *)strchr((char *)b64buffer, a);
    while (p){
        *p = '+';
        p = (u_char *)strchr((char *)p, a);
    }
    u_char *q = (u_char *)strchr((char *)b64buffer, b);
    while (q){
        *q = '/';
        q = (u_char *)strchr((char *)q, b);
    }
    return b64buffer;
}

extern u_char *base64_decode(ngx_pool_t *pool, u_char* base64data, int** len) {
   BIO *b64 = NULL;
   BIO *bmem = NULL;
   size_t length = ngx_strlen((char *)base64data);
   size_t paddedLength;
   u_char *paddedb64data;
   if ( !((6*length%8==0)) )
   {
       int lcm = (length / 8 + 1) * 8;
       int n_pad = lcm - length;
       paddedLength =  length + n_pad + 1;
       paddedb64data = (u_char *) ngx_pcalloc(pool, paddedLength);
       ngx_cpystrn(paddedb64data, base64data, length+1);
       ngx_memset(paddedb64data+length, 61, n_pad);
       ngx_memset(paddedb64data+length+n_pad, 0, 1);
   }
   else
   {
       paddedLength = length + 1;
       paddedb64data = (u_char *) ngx_pcalloc(pool, paddedLength);
       ngx_cpystrn(paddedb64data, base64data, length+1);
       ngx_memset(paddedb64data+length, 0, 1);
   }
   u_char *retbuffer = (u_char *)ngx_pcalloc(pool, paddedLength);
   b64 = BIO_new(BIO_f_base64());
   BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
   bmem = BIO_new_mem_buf((void*)paddedb64data, paddedLength);
   bmem = BIO_push(b64, bmem);
   **len = BIO_read(bmem, retbuffer, paddedLength);
   BIO_free_all(bmem);
   return retbuffer;
}

extern BIGNUM* bignum_base64_decode(ngx_pool_t *pool, u_char* base64bignum, int* len) {
   BIGNUM* bn = NULL;
   u_char* data = base64_decode(pool, base64bignum, &len);
   if (*len) {
       bn = BN_bin2bn(data, *len, NULL);
   }
   ngx_pfree(pool, data);
   return bn;
}


extern u_char *jwk_to_pem_u_char(ngx_pool_t *pool, struct pubkey_t pubkey) {
    int *mod_hex_len = ngx_palloc(pool, sizeof(int));
    u_char* n_url_decode = base64_urlsafe_to_standard(pool, pubkey.modulus);
    BIGNUM *n = bignum_base64_decode(pool, n_url_decode, mod_hex_len);
    int *exp_hex_len = ngx_palloc(pool, sizeof(int));
    BIGNUM *e = bignum_base64_decode(pool, (u_char *)pubkey.exponent, exp_hex_len);
    RSA *RSAkey = RSA_new();
    RSA_set0_key(RSAkey, n, e, NULL);
    BIO* buf = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(buf, RSAkey);
    u_char *p;
    int readSize = (int)BIO_get_mem_data(buf, &p);
    u_char * dest = ngx_pcalloc(pool, readSize);
    ngx_memcpy(dest, p, readSize);
    ngx_pfree(pool, p);
    ngx_pfree(pool, n_url_decode);
    ngx_pfree(pool, mod_hex_len);
    ngx_pfree(pool, exp_hex_len);
    BIO_free_all(buf);
    return dest;
}