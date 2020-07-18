#ifndef _NGX_HTTP_JWT_CF_JWK_REQUEST_H
#define _NGX_HTTP_JWT_CF_JWK_REQUEST_H

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <curl/curl.h>
#include <jansson.h>

#include <ngx_core.h>

struct write_result {
    char *data;
    size_t size;
};

struct pubkey_t {
    char *exponent;
    char *modulus;
    u_char *certPEM;
};


size_t write_response(void *contents, size_t size, size_t nmemb, void *stream);
char *request(ngx_pool_t *pool, const char *url);
json_t *get_jwk(ngx_pool_t *pool, const char *URL);
int parse_jwk_to_pubkey(ngx_pool_t *pool, json_t *root, struct pubkey_t **keylist);


#endif /* _NGX_HTTP_JWK_CF_JSON_REQUEST_H */