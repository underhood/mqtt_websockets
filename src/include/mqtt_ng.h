#include <stdint.h>

#include "ringbuffer.h"

struct mqtt_ng_client;

struct mqtt_connect {
    
};

/* free_fnc_t in general (in whatever function or struct it is used)
 * decides how the related data will be handled.
 * - If NULL the data are copied internally (causing malloc and later free)
 * - If pointer provided the free function pointed will be called when data are no longer needed
 *   to free associated memory. This is effectively transfering ownership of that pointer to the library.
 *   This also allows caller to provide custom free function other than system one.
 * - If == CALLER_RESPONSIBILITY the library will not copy the data pointed to and will not call free
 *   at the end. This is usefull to avoid copying memory (and associated malloc/free) when data are for
 *   example static. In this case caller has to guarantee the memory pointed to will be valid for entire duration
 *   it is needed. For example by freeing the data after PUBACK is received or by data being static.
 */
typedef void (*free_fnc_t)(void *ptr);
void _caller_responsibility(void *ptr);
#define CALLER_RESPONSIBILITY ((free_fnc_t)&_caller_responsibility)

/* Converts integer to MQTT Variable Byte Integer as per 1.5.5 of MQTT 5 specs
 * @param input value to be converted
 * @param output pointer to memory where output will be written to. Must allow up to 4 bytes to be written.
 * @return number of bytes written to output or <= 0 if error in which case contents of output are undefined
 */
int uint32_to_mqtt_vbi(uint32_t input, char *output);

struct mqtt_lwt_properties {
    char *will_topic;
    free_fnc_t will_topic_free;

    void *will_message;
    free_fnc_t will_message_free;
    size_t will_message_size;

    int will_qos;
    int will_retain;
};

struct mqtt_auth_properties {
    char *client_id;
    free_fnc_t client_id_free;
    char *username;
    free_fnc_t username_free;
    char *password;
    free_fnc_t password_free;
};

int mqtt_ng_connect(struct mqtt_ng_client *client,
                    struct mqtt_auth_properties *auth,
                    struct mqtt_lwt_properties *lwt,
                    uint8_t clean_start,
                    uint16_t keep_alive);

typedef ssize_t (*mqtt_ng_send_fnc_t)(void *user_ctx, const void* buf, size_t len);

struct mqtt_ng_init {
    mqtt_wss_log_ctx_t log;
    rbuf_t data_in;
    mqtt_ng_send_fnc_t data_out_fnc;
    void *user_ctx;

    void (*connack_callback)(void* user_ctx, int connack_reply);
};

struct mqtt_ng_client *mqtt_ng_init(struct mqtt_ng_init *settings);

int mqtt_ng_sync(struct mqtt_ng_client *client);