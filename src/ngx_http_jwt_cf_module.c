/*
 * Copyright (C) 2018 Tesla Government
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 *
 * https://github.com/TeslaGov/ngx-http-auth-jwt-module
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <jwt.h>

#include <jansson.h>


#include "ngx_http_jwt_cf_jwk_request.h"
#include "ngx_http_jwt_cf_jwk_decode.h"

#include "ngx_http_jwt_cf_header_processing.h"
#include "ngx_http_jwt_cf_string.h"

typedef struct {
	ngx_str_t    jwt_cf_login_url;
	ngx_str_t	 jwt_cf_cert_url;
	ngx_flag_t   jwt_cf_enabled;
	ngx_flag_t   jwt_cf_redirect;
	ngx_str_t    jwt_cf_validation_type;
	ngx_str_t	 jwt_cf_claim_key;
	ngx_str_t	 jwt_cf_claim_value;

} ngx_http_jwt_cf_loc_conf_t;

static ngx_int_t ngx_http_jwt_cf_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_jwt_cf_handler(ngx_http_request_t *r);
static void * ngx_http_jwt_cf_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_jwt_cf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char * getJwt(ngx_http_request_t *r, ngx_str_t jwt_cf_validation_type);
static struct pubkey_t * getPublicKey(ngx_http_request_t *r, ngx_str_t jwt_cf_cert_url, int *numkeys);

static ngx_command_t ngx_http_jwt_cf_commands[] = {

	{ ngx_string("jwt_cf_login_url"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_jwt_cf_loc_conf_t, jwt_cf_login_url),
		NULL },

	{ ngx_string("jwt_cf_cert_url"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_jwt_cf_loc_conf_t, jwt_cf_cert_url),
		NULL },

	{ ngx_string("jwt_cf_enabled"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_jwt_cf_loc_conf_t, jwt_cf_enabled),
		NULL },

	{ ngx_string("jwt_cf_redirect"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_jwt_cf_loc_conf_t, jwt_cf_redirect),
		NULL },

	{ ngx_string("jwt_cf_validation_type"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_jwt_cf_loc_conf_t, jwt_cf_validation_type),
		NULL },

	{ ngx_string("jwt_cf_claim_key"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_jwt_cf_loc_conf_t, jwt_cf_claim_key),
		NULL },

	{ ngx_string("jwt_cf_claim_value"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_jwt_cf_loc_conf_t, jwt_cf_claim_value),
		NULL },

	ngx_null_command
};


static ngx_http_module_t ngx_http_jwt_cf_module_ctx = {
	NULL,                        /* preconfiguration */
	ngx_http_jwt_cf_init,      /* postconfiguration */

	NULL,                        /* create main configuration */
	NULL,                        /* init main configuration */

	NULL,                        /* create server configuration */
	NULL,                        /* merge server configuration */

	ngx_http_jwt_cf_create_loc_conf,      /* create location configuration */
	ngx_http_jwt_cf_merge_loc_conf       /* merge location configuration */
};


ngx_module_t ngx_http_jwt_cf_module = {
	NGX_MODULE_V1,
	&ngx_http_jwt_cf_module_ctx,     /* module context */
	ngx_http_jwt_cf_commands,        /* module directives */
	NGX_HTTP_MODULE,                   /* module type */
	NULL,                              /* init master */
	NULL,                              /* init module */
	NULL,                              /* init process */
	NULL,                              /* init thread */
	NULL,                              /* exit thread */
	NULL,                              /* exit process */
	NULL,                              /* exit master */
	NGX_MODULE_V1_PADDING
};


static ngx_int_t ngx_http_jwt_cf_handler(ngx_http_request_t *r)
{
	char* jwtCookieValChrPtr;
	char* return_url;
	ngx_http_jwt_cf_loc_conf_t *jwtcf;
	jwt_t *jwt = NULL;
	struct pubkey_t *pubkey;
	int *numkeys;
	int jwtParseReturnCode;
	jwt_alg_t alg;
	const char* claim_value;
	time_t exp;
	time_t now;
	ngx_str_t jwt_cf_claim_key;
	ngx_str_t jwt_cf_claim_value;
	int keylen;
	
	jwtcf = ngx_http_get_module_loc_conf(r, ngx_http_jwt_cf_module);
	
	if (!jwtcf->jwt_cf_enabled) 
	{
		return NGX_DECLINED;
	}

	// pass through options requests without token authentication
	if (r->method == NGX_HTTP_OPTIONS)
	{
		return NGX_DECLINED;
	}
	
	jwtCookieValChrPtr = getJwt(r, jwtcf->jwt_cf_validation_type);
	if (jwtCookieValChrPtr == NULL)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to find a jwt");
		goto redirect;
	}

	// Obtain public key via request to Cloudflare
	numkeys = ngx_palloc(r->pool, sizeof(int));
	pubkey =  getPublicKey(r, jwtcf->jwt_cf_cert_url, numkeys);
	int validateN = 0;
	
	// validate the jwt
	do {
		keylen = strlen((char*)pubkey[validateN].certPEM);
		jwtParseReturnCode = jwt_decode(&jwt, jwtCookieValChrPtr, pubkey[validateN].certPEM, keylen);
		validateN++;
	} while (jwtParseReturnCode !=0 && validateN<*numkeys);
	

	if (jwtParseReturnCode != 0)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to parse jwt");
		goto redirect;
	}
	
	// validate the algorithm
	alg = jwt_get_alg(jwt);
	if (alg != JWT_ALG_HS256 && alg != JWT_ALG_RS256)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "invalid algorithm in jwt %d", alg);
		goto redirect;
	}
	
	// validate the exp date of the JWT
	exp = (time_t)jwt_get_grant_int(jwt, "exp");
	now = time(NULL);
	if (exp < now)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "the jwt has expired");
		goto redirect;
	}

	// validate the claim
	jwt_cf_claim_key = jwtcf->jwt_cf_claim_key;
	jwt_cf_claim_value = jwtcf->jwt_cf_claim_value;
	const u_char * jwt_cf_claim_key_uchar = jwt_cf_claim_key.data;
	if (jwt_cf_claim_key.len != 0)
	{
		claim_value = jwt_get_grants_json(jwt, (const char *)jwt_cf_claim_key_uchar);
		if (claim_value == NULL)
		{
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "the jwt does not contain claim %V", jwt_cf_claim_key.data);
		}
		
		else if (ngx_strstr(claim_value, jwt_cf_claim_value.data)==NULL)
		{
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "the jwt claim does not match the correct value");
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "the presented claim was: %s", claim_value);
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "the expected value is: %s", jwt_cf_claim_value.data);
			goto redirect;
		}
	}
	jwt_free(jwt);

	return NGX_OK;
	
	redirect:

		if (jwt)
		{
			jwt_free(jwt);
		}

		r->headers_out.location = ngx_list_push(&r->headers_out.headers);
		
		if (r->headers_out.location == NULL) 
		{
			ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		}

		r->headers_out.location->hash = 1;
		r->headers_out.location->key.len = sizeof("Location") - 1;
		r->headers_out.location->key.data = (u_char *) "Location";

		if (r->method == NGX_HTTP_GET)
		{
			int loginlen;
			char * scheme;
			ngx_str_t server;
			ngx_str_t uri_variable_name = ngx_string("request_uri");
			ngx_int_t uri_variable_hash;
			ngx_http_variable_value_t * request_uri_var;
			ngx_str_t uri;
			ngx_str_t uri_escaped;
			uintptr_t escaped_len;

			loginlen = jwtcf->jwt_cf_login_url.len;

			scheme = "https";
			server = r->headers_in.server;

			// get the URI
			uri_variable_hash = ngx_hash_key(uri_variable_name.data, uri_variable_name.len);
			request_uri_var = ngx_http_get_variable(r, &uri_variable_name, uri_variable_hash);

			// get the URI
			if(request_uri_var && !request_uri_var->not_found && request_uri_var->valid)
			{
				// ideally we would like the uri with the querystring parameters
				uri.data = ngx_palloc(r->pool, request_uri_var->len);
				uri.len = request_uri_var->len;
				ngx_memcpy(uri.data, request_uri_var->data, request_uri_var->len);

				// ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "found uri with querystring %s", ngx_str_t_to_char_ptr(r->pool, uri));
			}
			else
			{
				// fallback to the querystring without params
				uri = r->uri;

				// ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "fallback to querystring without params");
			}

			// escape the URI
			escaped_len = 2 * ngx_escape_uri(NULL, uri.data, uri.len, NGX_ESCAPE_ARGS) + uri.len;
			uri_escaped.data = ngx_palloc(r->pool, escaped_len);
			uri_escaped.len = escaped_len;
			ngx_escape_uri(uri_escaped.data, uri.data, uri.len, NGX_ESCAPE_ARGS);

			r->headers_out.location->value.len = loginlen + sizeof("?return_url=") - 1 + strlen(scheme) + sizeof("://") - 1 + server.len + uri_escaped.len;
			return_url = ngx_palloc(r->pool, r->headers_out.location->value.len);
			ngx_memcpy(return_url, jwtcf->jwt_cf_login_url.data, jwtcf->jwt_cf_login_url.len);
			int return_url_idx = jwtcf->jwt_cf_login_url.len;
			ngx_memcpy(return_url+return_url_idx, "?return_url=", sizeof("?return_url=") - 1);
			return_url_idx += sizeof("?return_url=") - 1;
			ngx_memcpy(return_url+return_url_idx, scheme, strlen(scheme));
			return_url_idx += strlen(scheme);
			ngx_memcpy(return_url+return_url_idx, "://", sizeof("://") - 1);
			return_url_idx += sizeof("://") - 1;
			ngx_memcpy(return_url+return_url_idx, server.data, server.len);
			return_url_idx += server.len;
			ngx_memcpy(return_url+return_url_idx, uri_escaped.data, uri_escaped.len);
			return_url_idx += uri_escaped.len;
			r->headers_out.location->value.data = (u_char *)return_url;

			// ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "return_url: %s", ngx_str_t_to_char_ptr(r->pool, r->headers_out.location->value));
		}
		else
		{
			// for non-get requests, redirect to the login page without a return URL
			r->headers_out.location->value.len = jwtcf->jwt_cf_login_url.len;
			r->headers_out.location->value.data = jwtcf->jwt_cf_login_url.data;
		}

		if (jwtcf->jwt_cf_redirect)
		{
			return NGX_HTTP_MOVED_TEMPORARILY;
		}
		else
		{
			return NGX_HTTP_UNAUTHORIZED;
		}
}


static ngx_int_t ngx_http_jwt_cf_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt        *h;
	ngx_http_core_main_conf_t  *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (h == NULL) 
	{
		return NGX_ERROR;
	}

	*h = ngx_http_jwt_cf_handler;

	return NGX_OK;
}


static void *
ngx_http_jwt_cf_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_jwt_cf_loc_conf_t *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_jwt_cf_loc_conf_t));
	if (conf == NULL) 
	{
		return NULL;
	}
	
	// set the flag to unset
	conf->jwt_cf_enabled = (ngx_flag_t) -1;
	conf->jwt_cf_redirect = (ngx_flag_t) -1;

	ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "Created Location Configuration");
	
	return conf;
}


static char *
ngx_http_jwt_cf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_jwt_cf_loc_conf_t *prev = parent;
	ngx_http_jwt_cf_loc_conf_t *conf = child;

	ngx_conf_merge_str_value(conf->jwt_cf_login_url, prev->jwt_cf_login_url, "");
	ngx_conf_merge_str_value(conf->jwt_cf_cert_url, prev->jwt_cf_cert_url, "");
	ngx_conf_merge_str_value(conf->jwt_cf_validation_type, prev->jwt_cf_validation_type, "");
	ngx_conf_merge_str_value(conf->jwt_cf_claim_key, prev->jwt_cf_claim_key, "aud");
	ngx_conf_merge_str_value(conf->jwt_cf_claim_value, prev->jwt_cf_claim_value, "");
	
	if (conf->jwt_cf_enabled == ((ngx_flag_t) -1)) 
	{
		conf->jwt_cf_enabled = (prev->jwt_cf_enabled == ((ngx_flag_t) -1)) ? 0 : prev->jwt_cf_enabled;
	}

	if (conf->jwt_cf_redirect == ((ngx_flag_t) -1))
	{
		conf->jwt_cf_redirect = (prev->jwt_cf_redirect == ((ngx_flag_t) -1)) ? 0 : prev->jwt_cf_redirect;
	}

	return NGX_CONF_OK;
}

static char * getJwt(ngx_http_request_t *r, ngx_str_t jwt_cf_validation_type)
{
	static const ngx_str_t authorizationHeaderName = ngx_string("Authorization");
	ngx_table_elt_t *authorizationHeader;
	char* jwtCookieValChrPtr = NULL;
	ngx_str_t jwtCookieVal;
	ngx_int_t n;
	ngx_str_t authorizationHeaderStr;

	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "jwt_cf_validation_type.len %d", jwt_cf_validation_type.len);

	if (jwt_cf_validation_type.len == 0 || (jwt_cf_validation_type.len == sizeof("AUTHORIZATION") - 1 && ngx_strncmp(jwt_cf_validation_type.data, "AUTHORIZATION", sizeof("AUTHORIZATION") - 1)==0))
	{
		// using authorization header
		authorizationHeader = search_headers_in(r, authorizationHeaderName.data, authorizationHeaderName.len);
		if (authorizationHeader != NULL)
		{
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Found authorization header len %d", authorizationHeader->value.len);

			authorizationHeaderStr.data = authorizationHeader->value.data + sizeof("Bearer ") - 1;
			authorizationHeaderStr.len = authorizationHeader->value.len - (sizeof("Bearer ") - 1);

			jwtCookieValChrPtr = ngx_str_t_to_char_ptr(r->pool, authorizationHeaderStr);

			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Authorization header: %s", jwtCookieValChrPtr);
		}
	}
	else if (jwt_cf_validation_type.len > sizeof("COOKIE=") && ngx_strncmp(jwt_cf_validation_type.data, "COOKIE=", sizeof("COOKIE=") - 1)==0)
	{
		jwt_cf_validation_type.data += sizeof("COOKIE=") - 1;
		jwt_cf_validation_type.len -= sizeof("COOKIE=") - 1;

		// get the cookie
		// TODO: the cookie name could be passed in dynamicallly
		n = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &jwt_cf_validation_type, &jwtCookieVal);
		if (n != NGX_DECLINED) 
		{
			jwtCookieValChrPtr = ngx_str_t_to_char_ptr(r->pool, jwtCookieVal);
		}
	}

	return jwtCookieValChrPtr;
}

static struct pubkey_t *getPublicKey(ngx_http_request_t *r, ngx_str_t jwt_cf_cert_url, int *numkeys)
{
	json_t *jwkey;
	struct pubkey_t *keylist;

	jwkey = get_jwk(r->pool, (char*)jwt_cf_cert_url.data);
	*numkeys = parse_jwk_to_pubkey(r->pool, jwkey, &keylist);	
	if (!*numkeys)
	{
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Unable to parse java web key(s)");
	}
	for (int i=0; i<*numkeys; i++){
    	keylist[i].certPEM = jwk_to_pem_u_char(r->pool, keylist[i]);
	}
	return keylist;
}





