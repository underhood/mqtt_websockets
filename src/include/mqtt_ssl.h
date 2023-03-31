#ifndef MQTT_WEBSOCKET_SSL_H_
# define MQTT_WEBSOCKET_SSL_H_ 1

#if defined(ENABLE_HTTPS_WITH_OPENSSL)
#include <openssl/err.h>
#include <openssl/ssl.h>
#elif defined(ENABLE_HTTPS_WITH_WOLFSSL)
#include <wolfssl/version.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

#include <wolfssl/openssl/sha.h>
#include <wolfssl/openssl/evp.h>
#endif

#endif
