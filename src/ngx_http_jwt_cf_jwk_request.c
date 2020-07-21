/*
 * Copyright (C) 2020 Tom Fahey
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 *
 * https://github.com/TomFahey/nginx-cloudflare-jwt-checker
 */

#include "ngx_http_jwt_cf_jwk_request.h"

#include <ngx_core.h>

#define BUFFER_SIZE (64 * 1024) /*  64KB */
#define URL_SIZE   512


size_t write_response(void *contents, size_t size, size_t nmemb, void *stream) {
    struct write_result *result = (struct write_result *)stream;

    char *ptr = realloc(result->data, result->size + size * nmemb + 1);

    if (ptr == NULL) {
        /* out of memory! */
        //fprintf(stderr, "error: too small buffer\n");
        return 0;
    }

    result->data = ptr;
    ngx_memcpy(&(result->data[result->size]), contents, size * nmemb);
    result->size += size * nmemb;
    result->data[result->size] = 0;

    return size * nmemb;
}

char *request(ngx_pool_t *pool, const char *url) {
    CURL *curl = NULL;
    CURLcode status;
    char *data = NULL;
    long code;

    curl_global_init(CURL_GLOBAL_ALL);

    /* init the curl session */
    curl = curl_easy_init();
    if (!curl)
    {
        if (data)
            ngx_pfree(pool, data);
        if (curl)
            curl_easy_cleanup(curl);
        curl_global_cleanup();
        return NULL;
    }
    data = ngx_palloc(pool, BUFFER_SIZE);
    if (!data)
    {
        if (data)
            ngx_pfree(pool, data);
        if (curl)
            curl_easy_cleanup(curl);
        curl_global_cleanup();
        return NULL;
    }

    struct write_result write_result = {.data = data, .size = 0};

    /* specify URL to get */
    curl_easy_setopt(curl, CURLOPT_URL, url);

    /* send all data to this function */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&write_result);

    status = curl_easy_perform(curl);
    if (status != 0) {
        //fprintf(stderr, "error: unable to request data from %s:\n", url);
        //fprintf(stderr, "%s\n", curl_easy_strerror(status));
        if (data)
            ngx_pfree(pool, data);
        if (curl)
            curl_easy_cleanup(curl);
        curl_global_cleanup();
        return NULL;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if (code != 200) {
        //fprintf(stderr, "error: server responded with code %ld\n", code);
        if (data)
            ngx_pfree(pool, data);
        if (curl)
            curl_easy_cleanup(curl);
        curl_global_cleanup();
        return NULL;
    }

    curl_easy_cleanup(curl);
    curl_global_cleanup();

    /* zero-terminate the result */
    data[write_result.size] = '\0';

    return data;
}


json_t *get_jwk(ngx_pool_t *pool, const char * URL) {
    char *text;

    json_t *root;
    json_error_t *error = NULL;

    text = request(pool, URL);
    if (!text)
        return NULL;

    root = json_loads(text, 0, error);
    ngx_pfree(pool, text);

    if (!root) {
        //fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
        return NULL;
    }

    if (!json_is_object(root)) {
        //fprintf(stderr, "error: root is not an object\n");
        json_decref(root);
        return NULL;
    }

    return root;

}

int parse_jwk_to_pubkey(ngx_pool_t *pool, json_t *root, struct pubkey_t **keylist)
{
    json_t *keys;

    keys = json_object_get(root, "keys");
    if (!json_is_array(keys)) {
        //fprintf(stderr, "error: keys is not an array\n");
        json_decref(root);
        return 1;
    }

    size_t numkeys = json_array_size(keys);
    *keylist = ngx_palloc(pool, numkeys*(sizeof(**keylist)));

    for (size_t i=0; i<numkeys; i++){

        json_t *data, *e, *n = NULL;

        data = json_array_get(keys, 0);
        if (!json_is_object(data)) {
            //fprintf(stderr, "error: data is not an object\n");
            json_decref(root);
            return 1;
        }

        e = json_object_get(data, "e");
        if (!json_is_string(e)) {
            //fprintf(stderr, "error: e is not a string\n");
            json_decref(root);
            return 1;
        }

        n = json_object_get(data, "n");
        if (!json_is_string(n)) {
            //fprintf(stderr, "error: n is not a string\n");
            json_decref(root);
            return 1;
        }

        int n_len = json_string_length(n);
        int e_len = json_string_length(e);

        (*keylist)[i].modulus = (char *)ngx_pcalloc(pool, n_len+1);
        (*keylist)[i].exponent = (char *)ngx_pcalloc(pool, e_len+1);
        ngx_memcpy((*keylist)[i].modulus, json_string_value(n), n_len);
        ngx_memcpy((*keylist)[i].exponent, json_string_value(e), e_len);

    }

    return numkeys;
}