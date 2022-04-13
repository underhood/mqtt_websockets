#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common_internal.h"
#include "mqtt_constants.h"
#include "mqtt_wss_log.h"
#include "mqtt_ng.h"

#define UNIT_LOG_PREFIX "mqtt_client: "
#define FATAL(fmt, ...) mws_fatal(client->log, UNIT_LOG_PREFIX fmt, ##__VA_ARGS__)
#define ERROR(fmt, ...) mws_error(client->log, UNIT_LOG_PREFIX fmt, ##__VA_ARGS__)
#define WARN(fmt, ...)  mws_warn (client->log, UNIT_LOG_PREFIX fmt, ##__VA_ARGS__)
#define INFO(fmt, ...)  mws_info (client->log, UNIT_LOG_PREFIX fmt, ##__VA_ARGS__)
#define DEBUG(fmt, ...) mws_debug(client->log, UNIT_LOG_PREFIX fmt, ##__VA_ARGS__)

#define BUFFER_FRAG_GARBAGE_COLLECT 0x01
// as buffer fragment can point to both
// external data and data in the same buffer
// we mark the latter case with BUFFER_FRAG_DATA_FOLLOWING
#define BUFFER_FRAG_DATA_FOLLOWING  0x02
struct buffer_fragment {
    size_t len;
    uint16_t flags;
    void (*free_fnc)(void *ptr);
    char *data;
    struct data_fragment *next;
};

// buffer used for MQTT headers only
// not for actual data sent
struct header_buffer {
    size_t buffer_size;
    char *data;
    char *tail;
    struct buffer_fragment *tail_frag;
};

struct mqtt_ng_client {
    struct header_buffer buf;
    mqtt_wss_log_ctx_t log;
};

int uint32_to_mqtt_vbi(uint32_t input, char *output) {
    int i = 1;
    *output = 0;

    /* MQTT 5 specs allows max 4 bytes of output
       making it 0xFF, 0xFF, 0xFF, 0x7F
       representing number 268435455 decimal
       see 1.5.5. Variable Byte Integer */
    if(input >= 256 * 1024 * 1024)
        return 0;

    while(input) {
        output[i-1] = input & 0x7F;
        input >>= 7;
        if (input)
            output[i-1] |= 0x80;
        i++;
    }
    return i;
}

#define HEADER_BUFFER_SIZE 1024*1024
struct mqtt_ng_client *mqtt_ng_init(mqtt_wss_log_ctx_t log) {
    struct mqtt_ng_client *client = calloc(1, sizeof(struct mqtt_ng_client) + HEADER_BUFFER_SIZE);
    if (client == NULL)
        return NULL;
    
    client->buf.buffer_size = HEADER_BUFFER_SIZE;
    client->buf.data = ((char*)client) + sizeof(struct mqtt_ng_client);
    client->buf.tail = client->buf.data;
    client->buf.tail_frag = NULL;

    client->log = log;

    return client;
}

#define BUFFER_BYTES_USED(buf) ((size_t)((buf)->tail - (buf)->data))
#define BUFFER_BYTES_AVAILABLE(buf) (HEADER_BUFFER_SIZE - BUFFER_BYTES_USED(buf))

static struct buffer_fragment *buffer_new_frag(struct mqtt_ng_client *client)
{
    if (BUFFER_BYTES_AVAILABLE(&client->buf) < sizeof(struct buffer_fragment))
        return NULL;

    struct buffer_fragment *frag = (struct buffer_fragment *)client->buf.tail;
    client->buf.tail += sizeof(*frag);
    client->buf.tail_frag = frag;

    frag->data = client->buf.tail;

    return frag;
}

// this is fixed part of variable header for connect packet
// mqtt-v5.0-cs1, 3.1.2.1, 2.1.2.2
static const char mqtt_protocol_name_frag[] =
    { 0x00, 0x04, 'M', 'Q', 'T', 'T', MQTT_VERSION_5_0 };

#define MQTT_UTF8_STRING_SIZE(string) (2 + strlen(string))

// see 1.5.5
#define MQTT_VARSIZE_INT_BYTES(value) ( value > 2097152 ? 4 : ( value > 16384 ? 3 : ( value > 128 ? 2 : 1 ) ) )

static size_t mqtt_ng_connect_size(struct mqtt_auth_properties *auth,
                    struct mqtt_lwt_properties *lwt)
{
    // First get the size of payload + variable header
    size_t size =
        + sizeof(mqtt_protocol_name_frag) /* Proto Name and Version */
        + 1 /* Connect Flags */
        + 2 /* Keep Alive */
        + 1 /* 3.1.2.11.1 Property Length - for now 0, TODO TODO*/;

    // CONNECT payload. 3.1.3
    if (auth->client_id)
        size += MQTT_UTF8_STRING_SIZE(auth->client_id);

    // 3.1.3.2 will properties TODO TODO
    size += 1;

    // 3.1.3.3
    if (lwt->will_topic)
        size += MQTT_UTF8_STRING_SIZE(lwt->will_topic);
    
    // 3.1.3.4 will payload
    if (lwt->will_message) {
        size += 2 + lwt->will_message_size;
    }

    // 3.1.3.5
    if (auth->username)
        size += MQTT_UTF8_STRING_SIZE(auth->username);

    // 3.1.3.6
    if (auth->password)
        size += MQTT_UTF8_STRING_SIZE(auth->password);

    return size;
}

#define REQUEST_BUFFER_BYTES(client, needed) \
    { if (BUFFER_BYTES_AVAILABLE(&client->buf) < (size_t)needed) { \
        ERROR("Not enough bytes available in header buffer. Required: %zu, Available: %zu. mqtt_ng.c:%d", needed, BUFFER_BYTES_AVAILABLE(&client->buf), __LINE__); \
        return 1; \
      } else { \
          client->buf.tail+=needed; \
      } \
    }

int mqtt_ng_connect(struct mqtt_ng_client *client,
                    struct mqtt_auth_properties *auth,
                    struct mqtt_lwt_properties *lwt,
                    uint8_t connect_flags,
                    uint16_t keep_alive)
{
    // Sanity Checks First (are given parameters correct and up to MQTT spec)
    if (!auth->client_id) {
        ERROR("ClientID must be set. [MQTT-3.1.3-3]");
        return 1;
    }

    size_t len = strlen(auth->client_id);
    if (!len) {
        // [MQTT-3.1.3-6] server MAY allow empty client_id and treat it
        // as specific client_id (not same as client_id not given)
        // however server MUST allow ClientIDs between 1-23 bytes [MQTT-3.1.3-5]
        // so we will warn client server might not like this and he is using it
        // at his own risk!
        WARN("client_id provided is empty string. This might not be allowed by server [MQTT-3.1.3-6]");
    }
    if(len > MQTT_MAX_CLIENT_ID) {
        // [MQTT-3.1.3-5] server MUST allow client_id length 1-32
        // server MAY allow longer client_id, if user provides longer client_id
        // warn them he is doing so at his own risk!
        WARN("client_id provided is longer than 23 bytes, server might not allow that [MQTT-3.1.3-5]");
    }

    if (lwt && lwt->will_message && lwt->will_message_size > 65535) {
        ERROR("Will message cannot be longer than 65535 bytes due to MQTT protocol limitations [MQTT-3.1.3.4] and [MQTT-1.5.6]");
        return 1;
    }

    if (lwt && lwt->will_qos > MQTT_MAX_QOS) {
        // [MQTT-3-1.2-12]
        ERROR("QOS for LWT message is bigger than max");
        return 1;
    }


    // >> START THE RODEO <<

    // Calculate the resulting message size sans fixed MQTT header
    size_t size = mqtt_ng_connect_size(auth, lwt);

    // Start generating the message
    struct buffer_fragment *frag = buffer_new_frag(client);
    if (frag == NULL) {
        ERROR("Can't generate CONNECT packet. Not enough space in MQTT header buffer for new fragment descriptor.");
        return 1;
    }

    // MQTT Fixed Header
    size_t needed_bytes = 1 /* Packet type */ + MQTT_VARSIZE_INT_BYTES(size) + sizeof(mqtt_protocol_name_frag) + 1 /* CONNECT FLAGS */ + 2 /* keepalive */;
    REQUEST_BUFFER_BYTES(client, needed_bytes);

    char *write = frag->data;
    *write++ = MQTT_CPT_CONNECT << 4;
    write += uint32_to_mqtt_vbi(size, write);

    memcpy(write, mqtt_protocol_name_frag, sizeof(mqtt_protocol_name_frag));
    write += sizeof(mqtt_protocol_name_frag);

    *write = 0;
    if (auth->username)
        *write &= MQTT_CONNECT_FLAG_USERNAME;
    if (auth->password)
        *write &= MQTT_CONNECT_FLAG_PASSWORD;
    if (lwt) {
        *write &= MQTT_CONNECT_FLAG_LWT;
        *write &= lwt->will_qos << MQTT_CONNECT_FLAG_QOS_BITSHIFT;
        if (lwt->will_retain)
            *write &= MQTT_CONNECT_FLAG_LWT_RETAIN;
    }


    return 0;
}
