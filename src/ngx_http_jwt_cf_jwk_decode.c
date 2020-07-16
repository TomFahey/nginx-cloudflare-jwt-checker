#include "ngx_http_jwt_cf_jwk_request.h"

#include <ngx_core.h>

#define PADDING "=========="

u_char *base64_urlsafe_to_standard(ngx_pool_t *pool, char* base64url) {
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

u_char *base64_decode(ngx_pool_t *pool, u_char* base64data, int* len) {
   BIO *b64, *bmem;
   size_t length = ngx_strlen((char *)base64data);
   size_t paddedLength;
   u_char *paddedb64data;
   if ( !((6*length%8==0)) )
   {
       int lcm = (length / 8 + 1) * 8;
       int n_pad = lcm - length;
       paddedLength =  length + n_pad;
       paddedb64data = (u_char *) ngx_pcalloc(pool, paddedLength+1);
       ngx_cpystrn(paddedb64data, base64data, length+1);
       ngx_memset(paddedb64data+length, 61, n_pad);
   }
   else
   {
       paddedb64data = (u_char *) ngx_pcalloc(pool, length+1);
       ngx_cpystrn(paddedb64data, base64data, length+1);
       paddedLength = length;
   }
   u_char *retbuffer = (u_char *)ngx_pcalloc(pool, paddedLength+1);
   b64 = BIO_new(BIO_f_base64());
   BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
   bmem = BIO_new_mem_buf((void*)paddedb64data, paddedLength);
   bmem = BIO_push(b64, bmem);
   *len = BIO_read(bmem, retbuffer, paddedLength);
   BIO_free_all(bmem);
   return retbuffer;
}

BIGNUM* bignum_base64_decode(ngx_pool_t *pool, u_char* base64bignum, int* len) {
   BIGNUM* bn = NULL;
   u_char* data = base64_decode(pool, base64bignum, len);
   if (*len) {
       bn = BN_bin2bn(data, *len, NULL);
   }
   ngx_pfree(pool, data);
   ngx_pfree(pool, len);
   return bn;
}


u_char *jwk_to_pem_u_char(ngx_pool_t *pool, char* modulus, char* exponent) {
    int mod_hex_len;
    u_char* n_url_decode = base64_urlsafe_to_standard(pool, modulus);
    BIGNUM *n = bignum_base64_decode(pool, n_url_decode, &mod_hex_len);
    int exp_hex_len;
    BIGNUM *e = bignum_base64_decode(pool, (u_char *)exponent, &exp_hex_len);
    RSA *pubkey = RSA_new();
    RSA_set0_key(pubkey, n, e, NULL);
    BIO* buf2 = BIO_new(BIO_s_mem());
    BIO* buf3 = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(buf2, pubkey);
    RSA_print(buf3, pubkey, 1);
    u_char *rsaOut;
    BIO_get_mem_data(buf3, &rsaOut);
    ngx_pfree(pool, rsaOut);
    u_char *p;
    int readSize = (int)BIO_get_mem_data(buf2, &p);
    u_char * dest = ngx_pcalloc(pool, readSize);
    ngx_memcpy(dest, p, readSize);
    ngx_pfree(pool, p);
    return dest;
}