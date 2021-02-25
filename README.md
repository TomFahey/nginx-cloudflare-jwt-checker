# Intro
This is an NGINX module based on that of [TeslaGov](https://github.com/TeslaGov/ngx-http-auth-jwt-module/), which I have 
extended to work with Cloudflare's [Access Service](https://teams.cloudflare.com/access/), which mandates the verification of
JWTs ([described here](https://developers.cloudflare.com/access/setting-up-access/validate-jwt-tokens)) in order to properly
authenticate requests made through Access.

(Un)fortunately, Cloudflare does not use a single, static public certificate for verification, but rather a pair of certificates,
available at an external endpoint, that are periodically rotated, with the intention that validation is performed dynamically using this
endpoint, rather than by referencing a long-lived public cert in a configuration file.

This extension therefore builds on the existing module by facilitating the use of the external endpoint as an Nginx directive,
as well as providing options for which JWT claims to validate, such as the Application Audience (AUD) Tag provided by Cloudflare.


## Installation

This module can be built as a static or dynamic one. The latter is assumed in the config file. 

To install the module, install the dependencies listed below, as well as downloading a copy of the Nginx source. From there,
you simply need to configure Nginx with the `--add-dynamic-module` option and then compile and install in the usual way.

```
git clone https://github.com/TomFahey/nginx-cloudflare-jwt-checker.git
wget https://nginx.org/download/nginx-1.18.0.tar.gz
tar -xzf nginx-1.18.0.tar.gz
cd nginx-1.18.0
./configure --add-dynamic-module=../nginx-cloudflare-jwt-checker
make
make install
```

The module can be enabled by adding the following `load_module` directive to your nginx.conf
configuration file, under the top-level (main) context:

```
load_module modules/ngx_http_jwt_cf_module.so;
```

## Dependencies
This module depends on the [JWT C Library](https://github.com/benmcollins/libjwt)

Transitively, that library depends on a JSON Parser called
[Jansson](https://github.com/akheron/jansson) as well as the OpenSSL library.

Also required is [libcurl](https://curl.haxx.se/libcurl/).

## NGINX Directives
The nginx directives differ slightly in this module from TeslaGov. Rather than specifying
the public cert value, you should provide the URL of the external endpoint for your Cloudflare
account's authentication domain e.g for an application reachable at 'myapp.mydomain.net',
the external endpoint would be `https://mydomain.cloudflareaccess.com/cdn-cgi/access/certs`.

The claim to be checked and it's corresponding value are also specified via the appropriate
directives. For example, to check the AUD claim of a request to the example above, the
following directives would apply:


```
server {
    ...
    jwt_cf_cert_url "https://mydomain.cloudflareaccess.com/cdn-cgi/access/certs";
    jwt_cf_login_url "https://myapp.mydomain.com/loginpage";
    ...

    location / {
        ...
        jwt_cf_enabled on;
        jwt_cf_validation_type COOKIE=CF_Authorization;
        jwt_cf_redirect off;
        jwt_cf_claim_key "AUD";
        jwt_cf_claim_value "YOUR_APPLICATION_AUDIENCE_TAG";
        ...
    }
    ...
}

```

As with the original module, a typical use would be to specify the external endpoint and login
url on the server level and then turn on any locations that you want to secure. 

You can choose whether to return a 301 redirect reponse or 401 unauthorised by changing the 
`jwt_cf_redirect` directive.
