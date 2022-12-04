**Keycloak token validator service**

A simple (and hopefully fast) token validation service for keycloak

Usage: rust_keycloak_token_validator [OPTIONS]

Options:
-k, --keycloak-keys-path <KEYCLOAK_KEYS_PATH>
Keycloak realm keys endpoint (normally certs endpoint). Also can be set by the env var KEYCLOAK_KEYS_PATH

-s, --service-port <SERVICE_PORT>
Port this service will listen. Also can be set by the env var SERVICE_PORT

-b, --bind-ip <BIND_IP>
Ip / interface that this service will listen. Also can be set by the env var BIND_IP

-d, --disable-cert-check <DISABLE_CERT_CHECK>
Allow keycloak self signed certificates (only for test purposes). Also can be set by the env var DISABLE_CERT_CHECK

-n, --number-of-workers <NUMBER_OF_WORKERS>
number of api workers/threads (default=1)

-h, --help
Print help information
