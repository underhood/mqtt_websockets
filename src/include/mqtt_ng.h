#include <stdint.h>

#include "ringbuffer.h"
#include "common_public.h"

struct mqtt_ng_client;

struct mqtt_connect {
    
};

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

int mqtt_ng_publish(struct mqtt_ng_client *client,
                    const char *topic,
                    free_fnc_t topic_free,
                    const void *msg,
                    free_fnc_t msg_free,
                    size_t msg_len,
                    uint8_t publish_flags,
                    uint16_t *packet_id);

struct mqtt_sub {
    char *topic;
    free_fnc_t topic_free;
    uint8_t options;
};

int mqtt_ng_subscribe(struct mqtt_ng_client *client, struct mqtt_sub *subscriptions, size_t subscription_count);

typedef ssize_t (*mqtt_ng_send_fnc_t)(void *user_ctx, const void* buf, size_t len);

struct mqtt_ng_init {
    mqtt_wss_log_ctx_t log;
    rbuf_t data_in;
    mqtt_ng_send_fnc_t data_out_fnc;
    void *user_ctx;

    void (*connack_callback)(void* user_ctx, int connack_reply);
    void (*msg_callback)(const char *topic, const void *msg, size_t msglen, int qos);
};

struct mqtt_ng_client *mqtt_ng_init(struct mqtt_ng_init *settings);

int mqtt_ng_sync(struct mqtt_ng_client *client);