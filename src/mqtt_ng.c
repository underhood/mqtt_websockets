#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <inttypes.h>

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

#define SMALL_STRING_DONT_FRAGMENT_LIMIT 128

#define MIN(a,b) (((a)<(b))?(a):(b))

#define LOCK_HDR_BUFFER(client) pthread_mutex_lock(&client->buf_mutex)
#define UNLOCK_HDR_BUFFER(client) pthread_mutex_unlock(&client->buf_mutex)

#define BUFFER_FRAG_GARBAGE_COLLECT         0x01
// some packets can be marked for garbage collection
// immediately when they are sent (e.g. sent PUBACK on QoS1)
#define BUFFER_FRAG_GARBAGE_COLLECT_ON_SEND 0x02
// as buffer fragment can point to both
// external data and data in the same buffer
// we mark the former case with BUFFER_FRAG_DATA_EXTERNAL
#define BUFFER_FRAG_DATA_EXTERNAL           0x04
// as single MQTT Packet can be stored into multiple
// buffer fragments (depending on copy requirements)
// this marks this fragment to be the first/last
#define BUFFER_FRAG_MQTT_PACKET_HEAD        0x10
#define BUFFER_FRAG_MQTT_PACKET_TAIL        0x20

typedef uint16_t buffer_frag_flag_t;
struct buffer_fragment {
    size_t len;
    size_t sent;
    buffer_frag_flag_t flags;
    void (*free_fnc)(void *ptr);
    char *data;

    uint16_t packet_id;

    // next is not NULL only if there is
    // another fragment for the same MQTT message
    // it doesn't point to next fragment in the buffer
    struct buffer_fragment *next;
};

typedef struct buffer_fragment *mqtt_msg_data;

// buffer used for MQTT headers only
// not for actual data sent
struct header_buffer {
    size_t buffer_size;
    char *data;
    char *tail;
    struct buffer_fragment *tail_frag;
};

enum mqtt_client_state {
    RAW = 0,
    CONNECT_PENDING,
    CONNECTING,
    CONNECTED, 
    ERROR
};

enum parser_state {
    MQTT_PARSE_FIXED_HEADER_PACKET_TYPE = 0,
    MQTT_PARSE_FIXED_HEADER_LEN,
    MQTT_PARSE_VARIABLE_HEADER,
    MQTT_PARSE_MQTT_PACKET_DONE
};

enum varhdr_parser_state {
    MQTT_PARSE_VARHDR_INITIAL = 0,
    MQTT_PARSE_VARHDR_OPTIONAL_REASON_CODE,
    MQTT_PARSE_VARHDR_PROPS,
    MQTT_PARSE_VARHDR_TOPICNAME,
    MQTT_PARSE_VARHDR_PACKET_ID,
    MQTT_PARSE_REASONCODES,
    MQTT_PARSE_PAYLOAD
};

struct mqtt_vbi_parser_ctx {
    char data[MQTT_VBI_MAXBYTES];
    uint8_t bytes;
    uint32_t result;
};

struct mqtt_property {
    uint32_t id;
    struct mqtt_property *next;
};

enum mqtt_properties_parser_state {
    PROPERTIES_LENGTH = 0,
    PROPERTY_ID
};

struct mqtt_properties_parser_ctx {
    enum mqtt_properties_parser_state state;
    struct mqtt_property *head;
    uint32_t properties_length;
    struct mqtt_vbi_parser_ctx vbi_parser_ctx;
    size_t bytes_consumed;
};

struct mqtt_connack {
    uint8_t flags;
    uint8_t reason_code;
};
struct mqtt_puback {
    uint16_t packet_id;
    uint8_t reason_code;
};

struct mqtt_suback {
    uint16_t packet_id;
    uint8_t *reason_codes;
    uint8_t reason_code_count;
    uint8_t reason_codes_pending;
};

struct mqtt_publish {
    uint16_t topic_len;
    char *topic;
    uint16_t packet_id;
    size_t data_len;
    char *data;
    uint8_t qos;
};

struct mqtt_ng_parser {
    rbuf_t received_data;

    uint8_t mqtt_control_packet_type;
    uint32_t mqtt_fixed_hdr_remaining_length;
    size_t mqtt_parsed_len;

    struct mqtt_vbi_parser_ctx vbi_parser;
    struct mqtt_properties_parser_ctx properties_parser;

    enum parser_state state;
    enum varhdr_parser_state varhdr_state;

    struct mqtt_property *varhdr_properties;

    union {
        struct mqtt_connack connack;
        struct mqtt_puback puback;
        struct mqtt_suback suback;
        struct mqtt_publish publish;
    } mqtt_packet;
};


struct mqtt_ng_client {
    struct header_buffer buf;
    // used while building new message
    // to be able to revert state easily
    // in case of error mid processing
    struct header_buffer rollback;
    pthread_mutex_t buf_mutex;

    enum mqtt_client_state client_state;

    mqtt_msg_data connect_msg;

    mqtt_wss_log_ctx_t log;

    mqtt_ng_send_fnc_t send_fnc_ptr;
    void *user_ctx;

    // time when last fragment of MQTT message was sent
    time_t time_of_last_send;

    struct buffer_fragment *sending_frag;
    struct buffer_fragment *sending_msg;

    struct mqtt_ng_parser parser;

    void (*puback_callback)(uint16_t packet_id);
    void (*connack_callback)(void* user_ctx, int connack_reply);
    void (*msg_callback)(const char *topic, const void *msg, size_t msglen, int qos);
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

    if(!input) {
        *output = 0;
        return 1;
    }

    while(input) {
        output[i-1] = input & MQTT_VBI_DATA_MASK;
        input >>= 7;
        if (input)
            output[i-1] |= MQTT_VBI_CONTINUATION_FLAG;
        i++;
    }
    return i - 1;
}

int mqtt_vbi_to_uint32(char *input, uint32_t *output) {
    // dont want to operate directly on output
    // as I want it to be possible for input and output
    // pointer to be the same
    uint32_t result = 0;
    uint32_t multiplier = 1;

    do {
        result += (uint32_t)(*input & MQTT_VBI_DATA_MASK) * multiplier;
        if (multiplier > 128*128*128)
            return 1;
        multiplier <<= 7;
    } while (*input++ & MQTT_VBI_CONTINUATION_FLAG);
    *output = result;
    return 0;
}

#ifdef TESTS
#include <stdio.h>
#define MQTT_VBI_MAXLEN 4
// we add extra byte to check we dont write out of bounds
// in case where 4 bytes are supposed to be written
static const char _mqtt_vbi_0[MQTT_VBI_MAXLEN + 1] = { 0x00, 0x00, 0x00, 0x00, 0x00 };
static const char _mqtt_vbi_127[MQTT_VBI_MAXLEN + 1] = { 0x7F, 0x00, 0x00, 0x00, 0x00 };
static const char _mqtt_vbi_128[MQTT_VBI_MAXLEN + 1] = { 0x80, 0x01, 0x00, 0x00, 0x00 };
static const char _mqtt_vbi_16383[MQTT_VBI_MAXLEN + 1] = { 0xFF, 0x7F, 0x00, 0x00, 0x00 };
static const char _mqtt_vbi_16384[MQTT_VBI_MAXLEN + 1] = { 0x80, 0x80, 0x01, 0x00, 0x00 };
static const char _mqtt_vbi_2097151[MQTT_VBI_MAXLEN + 1] = { 0xFF, 0xFF, 0x7F, 0x00, 0x00 };
static const char _mqtt_vbi_2097152[MQTT_VBI_MAXLEN + 1] = { 0x80, 0x80, 0x80, 0x01, 0x00 };
static const char _mqtt_vbi_268435455[MQTT_VBI_MAXLEN + 1] = { 0xFF, 0xFF, 0xFF, 0x7F, 0x00 };
static const char _mqtt_vbi_999999999[MQTT_VBI_MAXLEN + 1] = { 0x80, 0x80, 0x80, 0x80, 0x01 };

#define MQTT_VBI_TESTCASE(case, expected_len) \
    { \
    memset(buf, 0, MQTT_VBI_MAXLEN + 1); \
    int len; \
    if ((len=uint32_to_mqtt_vbi(case, buf)) != expected_len) { \
        fprintf(stderr, "uint32_to_mqtt_vbi(case:%d, line:%d): Incorrect length returned. Expected %d, Got %d\n", case, __LINE__, expected_len, len); \
        return 1; \
    } \
    if (memcmp(buf, _mqtt_vbi_ ## case, MQTT_VBI_MAXLEN + 1 )) { \
        fprintf(stderr, "uint32_to_mqtt_vbi(case:%d, line:%d): Wrong output\n", case, __LINE__); \
        return 1; \
    } }


int test_uint32_mqtt_vbi() {
    char buf[MQTT_VBI_MAXLEN + 1];

    MQTT_VBI_TESTCASE(0,         1)
    MQTT_VBI_TESTCASE(127,       1)
    MQTT_VBI_TESTCASE(128,       2)
    MQTT_VBI_TESTCASE(16383,     2)
    MQTT_VBI_TESTCASE(16384,     3)
    MQTT_VBI_TESTCASE(2097151,   3)
    MQTT_VBI_TESTCASE(2097152,   4)
    MQTT_VBI_TESTCASE(268435455, 4)

    memset(buf, 0, MQTT_VBI_MAXLEN + 1);
    int len;
    if ((len=uint32_to_mqtt_vbi(268435456, buf)) != 0) {
        fprintf(stderr, "uint32_to_mqtt_vbi(case:268435456, line:%d): Incorrect length returned. Expected 0, Got %d\n", __LINE__, len);
        return 1;
    }

    return 0;
}

#define MQTT_VBI2UINT_TESTCASE(case, expected_error) \
    { \
    uint32_t result; \
    int ret = mqtt_vbi_to_uint32(_mqtt_vbi_ ## case, &result); \
    if (ret && !(expected_error)) { \
        fprintf(stderr, "mqtt_vbi_to_uint(case:%d, line:%d): Unexpectedly Errored\n", (case), __LINE__); \
        return 1; \
    } \
    if (!ret && (expected_error)) { \
        fprintf(stderr, "mqtt_vbi_to_uint(case:%d, line:%d): Should return error but didnt\n", (case), __LINE__); \
        return 1; \
    } \
    if (!ret && result != (case)) { \
        fprintf(stderr, "mqtt_vbi_to_uint(case:%d, line:%d): Returned wrong result %d\n", (case), __LINE__, result); \
        return 1; \
    }}


int test_mqtt_vbi_to_uint32() {
    MQTT_VBI2UINT_TESTCASE(0,         0)
    MQTT_VBI2UINT_TESTCASE(127,       0)
    MQTT_VBI2UINT_TESTCASE(128,       0)
    MQTT_VBI2UINT_TESTCASE(16383,     0)
    MQTT_VBI2UINT_TESTCASE(16384,     0)
    MQTT_VBI2UINT_TESTCASE(2097151,   0)
    MQTT_VBI2UINT_TESTCASE(2097152,   0)
    MQTT_VBI2UINT_TESTCASE(268435455, 0)
    MQTT_VBI2UINT_TESTCASE(999999999, 1)
    return 0;
}
#endif /* TESTS */

#define HEADER_BUFFER_SIZE 1024*1024
//struct mqtt_ng_client *mqtt_ng_init(mqtt_wss_log_ctx_t log, rbuf_t data_in, mqtt_ng_send_fnc_t send_fnc, void *user_ctx) {
struct mqtt_ng_client *mqtt_ng_init(struct mqtt_ng_init *settings)
{
    struct mqtt_ng_client *client = calloc(1, sizeof(struct mqtt_ng_client) + HEADER_BUFFER_SIZE);
    if (client == NULL)
        return NULL;

    pthread_mutex_init(&client->buf_mutex, NULL);

    client->buf.buffer_size = HEADER_BUFFER_SIZE;
    client->buf.data = ((char*)client) + sizeof(struct mqtt_ng_client);
    client->buf.tail = client->buf.data;
    client->buf.tail_frag = NULL;

    // TODO just embed the struct into mqtt_ng_client
    client->parser.received_data = settings->data_in;
    client->send_fnc_ptr = settings->data_out_fnc;
    client->user_ctx = settings->user_ctx;

    client->log = settings->log;

    client->puback_callback = settings->puback_callback;
    client->connack_callback = settings->connack_callback;
    client->msg_callback = settings->msg_callback;

    return client;
}

// this helps with switch statements
// as they have to use integer type (not pointer)
enum memory_mode {
    MEMCPY,
    EXTERNAL_FREE_AFTER_USE,
    CALLER_RESPONSIBLE
};

static inline enum memory_mode ptr2memory_mode(void * ptr) {
    if (ptr == NULL)
        return MEMCPY;
    if (ptr == CALLER_RESPONSIBILITY)
        return CALLER_RESPONSIBLE;
    return EXTERNAL_FREE_AFTER_USE;
}

static inline uint8_t get_control_packet_type(uint8_t first_hdr_byte)
{
    return first_hdr_byte >> 4;
}

#define BUFFER_BYTES_USED(buf) ((size_t)((buf)->tail - (buf)->data))
#define BUFFER_BYTES_AVAILABLE(buf) (HEADER_BUFFER_SIZE - BUFFER_BYTES_USED(buf))
#define BUFFER_FIRST_FRAG(buf) ((struct buffer_fragment *)((buf)->tail_frag ? (buf)->data : NULL))

static struct buffer_fragment *buffer_new_frag(struct mqtt_ng_client *client, buffer_frag_flag_t flags)
{
    if (BUFFER_BYTES_AVAILABLE(&client->buf) < sizeof(struct buffer_fragment))
        return NULL;

    struct buffer_fragment *frag = (struct buffer_fragment *)client->buf.tail;
    memset(frag, 0, sizeof(*frag));
    client->buf.tail += sizeof(*frag);

    if (/*!((frag)->flags & BUFFER_FRAG_MQTT_PACKET_HEAD) &&*/ client->buf.tail_frag)
        client->buf.tail_frag->next = frag;

    client->buf.tail_frag = frag;

    frag->data = client->buf.tail;

    frag->flags = flags;

    return frag;
}

static void buffer_frag_free_data(struct buffer_fragment *frag)
{
    if ( frag->flags & BUFFER_FRAG_DATA_EXTERNAL ) {
        switch (ptr2memory_mode(frag->free_fnc)) {
            case MEMCPY:
                free(frag->data);
                break;
            case EXTERNAL_FREE_AFTER_USE:
                frag->free_fnc(frag->data);
                break;
            case CALLER_RESPONSIBLE:
                break;
        }
    }
}

#define frag_is_marked_for_gc(frag) ((frag->flags & BUFFER_FRAG_GARBAGE_COLLECT) || ((frag->flags & BUFFER_FRAG_GARBAGE_COLLECT_ON_SEND) && frag->sent == frag->len))

static void buffer_garbage_collect(struct mqtt_ng_client *client)
{
    LOCK_HDR_BUFFER(client);
    size_t shift_by = 0;
    struct buffer_fragment *frag = BUFFER_FIRST_FRAG(&client->buf);
    while (frag) {
        if (!frag_is_marked_for_gc(frag))
            break;

        buffer_frag_free_data(frag);

        frag = frag->next;
    }

    if (!frag) {
        client->buf.tail_frag = NULL;
        client->buf.tail = client->buf.data;
        UNLOCK_HDR_BUFFER(client);
        return;
    }

#ifdef ADDITIONAL_CHECKS
    if (!(frag->flags & BUFFER_FRAG_MQTT_PACKET_HEAD)) {
        UNLOCK_HDR_BUFFER(client);
        ERROR("Expected to find end of buffer (NULL) or next packet head!");
        return;
    }
#endif

    memmove(client->buf.data, frag, client->buf.tail - (char*)frag);
    frag = client->buf.data;
    do {
        client->buf.tail = (char*)frag + sizeof(struct buffer_fragment);
        client->buf.tail_frag = frag;
        if (!(frag->flags & BUFFER_FRAG_DATA_EXTERNAL)) {
            client->buf.tail_frag->data = client->buf.tail;
            client->buf.tail += frag->len;
        }
        if (frag->next != NULL)
            frag->next = client->buf.tail;
        frag = frag->next;
    } while(frag);

    UNLOCK_HDR_BUFFER(client);
}

int frag_set_external_data(mqtt_wss_log_ctx_t log, struct buffer_fragment *frag, void *data, size_t data_len, free_fnc_t data_free_fnc)
{
    if (frag->len) {
        // TODO?: This could potentially be done in future if we set rule
        // external data always follows in buffer data
        // could help reduce fragmentation in some messages but
        // currently not worth it considering time is tight
        mws_fatal(log, UNIT_LOG_PREFIX "INTERNAL ERROR: Cannot set external data to fragment already containing in buffer data!");
        return 1;
    }

    switch (ptr2memory_mode(data_free_fnc)) {
        case MEMCPY:
            frag->data = malloc(data_len);
            if (frag->data == NULL) {
                mws_error(log, UNIT_LOG_PREFIX "OOM while malloc @_optimized_add");
                return 1;
            }
            memcpy(frag->data, data, data_len);
            break;
        case EXTERNAL_FREE_AFTER_USE:
        case CALLER_RESPONSIBLE:
            frag->data = data;
            break;
    }
    frag->free_fnc = data_free_fnc;
    frag->len = data_len;

    frag->flags |= BUFFER_FRAG_DATA_EXTERNAL;
    return 0;
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

    if (lwt) {
        // 3.1.3.2 will properties TODO TODO
        size += 1;

        // 3.1.3.3
        if (lwt->will_topic)
            size += MQTT_UTF8_STRING_SIZE(lwt->will_topic);

        // 3.1.3.4 will payload
        if (lwt->will_message) {
            size += 2 + lwt->will_message_size;
        }
    }

    // 3.1.3.5
    if (auth->username)
        size += MQTT_UTF8_STRING_SIZE(auth->username);

    // 3.1.3.6
    if (auth->password)
        size += MQTT_UTF8_STRING_SIZE(auth->password);

    return size;
}

// Creates transaction
// saves state of buffer before any operation was done
// allowing for rollback if things go wrong
#define buffer_transaction_start(client) \
  { LOCK_HDR_BUFFER(client); \
    memcpy(&client->rollback, &client->buf, sizeof(client->buf)); }

#define buffer_transaction_commit(client) UNLOCK_HDR_BUFFER(client);

void buffer_transaction_rollback(struct mqtt_ng_client *client, struct buffer_fragment *frag)
{
    memcpy(&client->buf, &client->rollback, sizeof(client->buf));
    if (client->buf.tail_frag != NULL)
        client->buf.tail_frag->next = NULL;

    while(frag) {
        buffer_frag_free_data(frag);
        // we are not actually freeing the structure itself
        // just the data it manages
        // structure itself is in permanent buffer
        // which is locked by HDR_BUFFER lock
        frag = frag->next;
    }

    UNLOCK_HDR_BUFFER(client);
}

#define BUFFER_TRANSACTION_NEW_FRAG(client, flags, frag, on_fail) \
    { if(frag==NULL) { \
        frag = buffer_new_frag(client, (flags)); } \
      if(frag==NULL) { \
        ERROR("Failed to create new fragment. Buffer full. %s, %d", __FUNCTION__, __LINE__); \
        on_fail; \
      }}

#define CHECK_BYTES_AVAILABLE(client, needed, fail) \
    { if (BUFFER_BYTES_AVAILABLE(&client->buf) < (size_t)needed) { \
        ERROR("Not enough bytes available in header buffer. Required: %zu, Available: %zu. mqtt_ng.c:%d", needed, BUFFER_BYTES_AVAILABLE(&client->buf), __LINE__); \
        fail; } }

#define DATA_ADVANCE(bytes, frag) { size_t b = (bytes); client->buf.tail += b; (frag)->len += b; }

// TODO maybe just user client->buf.tail?
#define WRITE_POS(frag) (&(frag->data[frag->len]))

// [MQTT-1.5.2] Two Byte Integer
#define PACK_2B_INT(integer, frag) { *(uint16_t *)WRITE_POS(frag) = htobe16((integer)); \
            DATA_ADVANCE(sizeof(uint16_t), frag); }

static int _optimized_add(struct mqtt_ng_client *client, void *data, size_t data_len, free_fnc_t data_free_fnc, struct buffer_fragment **frag)
{
    if (data_len > SMALL_STRING_DONT_FRAGMENT_LIMIT) {
        if( (*frag = buffer_new_frag(client, BUFFER_FRAG_DATA_EXTERNAL)) == NULL ) {
            ERROR("Out of buffer space while generating the message");
            return 1;
        }
        if (frag_set_external_data(client->log, *frag, data, data_len, data_free_fnc)) {
            ERROR("Error adding external data to newly created fragment");
            return 1;
        }
        // we dont want to write to this fragment anymore
        *frag = NULL;
    } else if (data_len) {
        // if the data are small dont bother creating new fragments
        // store in buffer directly
        CHECK_BYTES_AVAILABLE(client, data_len, return 1);
        memcpy(client->buf.tail, data, data_len);
        DATA_ADVANCE(data_len, *frag);
    }
    return 0;
}


#include <stdio.h>
/*
 * Prints count chars of mem to console or log.
 */
void printMemory(const unsigned char mem[], int count)
{
    int i, k = 0;
    char hexbyte[11] = "";
    char hexline[126] = "";
    for (i=0; i<count; i++) { // traverse through mem until count is reached
        sprintf(hexbyte, "0x%02X ", mem[i]); // add current byte to hexbyte
        strcat(hexline, hexbyte); // add hexbyte to hexline
        // print line every 16 bytes or if this is the last for-loop
        if (((i+1)%16 == 0) && (i != 0) || (i+1==count)) {
            k++;
            // choose your favourite output:
            printf("l%d: %s\n",k , hexline); // print line to console
            //syslog(LOG_INFO, "l%d: %s",k , hexline); // print line to syslog
            //printk(KERN_INFO "l%d: %s",k , hexline); // print line to kernellog
            memset(&hexline[0], 0, sizeof(hexline)); // clear hexline array
        }
    }
}

void dump_buffer_fragment(struct buffer_fragment *frag)
{
    int i = 0;
    while(frag) {
        printf("Fragment %d, len %zu, flags", i++, frag->len);
        if (frag->flags & BUFFER_FRAG_GARBAGE_COLLECT) {
            printf(" BUFFER_FRAG_GARBAGE_COLLECT");
        }
        if (frag->flags & BUFFER_FRAG_GARBAGE_COLLECT_ON_SEND) {
            printf(" BUFFER_FRAG_GARBAGE_COLLECT_ON_SEND");
        }
        if (frag->flags & BUFFER_FRAG_DATA_EXTERNAL) {
            printf(" BUFFER_FRAG_DATA_EXTERNAL");
        }
        if (frag->flags & BUFFER_FRAG_MQTT_PACKET_HEAD) {
            printf(" BUFFER_FRAG_MQTT_PACKET_HEAD");
        }
        if (frag->flags & BUFFER_FRAG_MQTT_PACKET_TAIL) {
            printf(" BUFFER_FRAG_MQTT_PACKET_TAIL");
        }
        printf(":\n");
        printMemory(frag->data, frag->len);
        frag = frag->next;
    }
}

mqtt_msg_data mqtt_ng_generate_connect(struct mqtt_ng_client *client,
                                       struct mqtt_auth_properties *auth,
                                       struct mqtt_lwt_properties *lwt,
                                       uint8_t clean_start,
                                       uint16_t keep_alive)
{
    // Sanity Checks First (are given parameters correct and up to MQTT spec)
    if (!auth->client_id) {
        ERROR("ClientID must be set. [MQTT-3.1.3-3]");
        return NULL;
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

    if (lwt) {
        if (lwt->will_message && lwt->will_message_size > 65535) {
            ERROR("Will message cannot be longer than 65535 bytes due to MQTT protocol limitations [MQTT-3.1.3-4] and [MQTT-1.5.6]");
            return NULL;
        }

        if (!lwt->will_topic) { //TODO topic given with strlen==0 ? check specs
            ERROR("If will message is given will topic must also be given [MQTT-3.1.3.3]");
            return NULL;
        }

        if (lwt->will_qos > MQTT_MAX_QOS) {
            // refer to [MQTT-3-1.2-12]
            ERROR("QOS for LWT message is bigger than max");
            return NULL;
        }
    }

    // >> START THE RODEO <<
    buffer_transaction_start(client);

    // Calculate the resulting message size sans fixed MQTT header
    size_t size = mqtt_ng_connect_size(auth, lwt);

    // Start generating the message
    struct buffer_fragment *frag = NULL;
    mqtt_msg_data ret = NULL;

    BUFFER_TRANSACTION_NEW_FRAG(client, BUFFER_FRAG_MQTT_PACKET_HEAD, frag, goto fail_rollback );
    ret = frag;

    // MQTT Fixed Header
    size_t needed_bytes = 1 /* Packet type */ + MQTT_VARSIZE_INT_BYTES(size) + sizeof(mqtt_protocol_name_frag) + 1 /* CONNECT FLAGS */ + 2 /* keepalive */ + 1 /* Properties TODO now fixed 0*/;
    CHECK_BYTES_AVAILABLE(client, needed_bytes, goto fail_rollback);

    *WRITE_POS(frag) = MQTT_CPT_CONNECT << 4;
    DATA_ADVANCE(1, frag);
    DATA_ADVANCE(uint32_to_mqtt_vbi(size, WRITE_POS(frag)), frag);

    memcpy(WRITE_POS(frag), mqtt_protocol_name_frag, sizeof(mqtt_protocol_name_frag));
    DATA_ADVANCE(sizeof(mqtt_protocol_name_frag), frag);

    // [MQTT-3.1.2.3] Connect flags
    char *connect_flags = WRITE_POS(frag);
    *connect_flags = 0;
    if (auth->username)
        *connect_flags |= MQTT_CONNECT_FLAG_USERNAME;
    if (auth->password)
        *connect_flags |= MQTT_CONNECT_FLAG_PASSWORD;
    if (lwt) {
        *connect_flags |= MQTT_CONNECT_FLAG_LWT;
        *connect_flags |= lwt->will_qos << MQTT_CONNECT_FLAG_QOS_BITSHIFT;
        if (lwt->will_retain)
            *connect_flags |= MQTT_CONNECT_FLAG_LWT_RETAIN;
    }
    if (clean_start)
        *connect_flags |= MQTT_CONNECT_FLAG_CLEAN_START;

    DATA_ADVANCE(1, frag);

    PACK_2B_INT(keep_alive, frag);

    // TODO Property Length [MQTT-3.1.3.2.1] temporary fixed 0
    *WRITE_POS(frag) = 0;
    DATA_ADVANCE(1, frag);

    // [MQTT-3.1.3.1] Client identifier
    CHECK_BYTES_AVAILABLE(client, 2, goto fail_rollback);
    PACK_2B_INT(strlen(auth->client_id), frag);
    if (_optimized_add(client, auth->client_id, strlen(auth->client_id), auth->client_id_free, &frag))
        goto fail_rollback;

    if (lwt != NULL) {
        // Will Properties [MQTT-3.1.3.2]
        // TODO for now fixed 0
        BUFFER_TRANSACTION_NEW_FRAG(client, 0, frag, goto fail_rollback);
        CHECK_BYTES_AVAILABLE(client, 1, goto fail_rollback);
        *WRITE_POS(frag) = 0;
        DATA_ADVANCE(1, frag);

        // Will Topic [MQTT-3.1.3.3]
        CHECK_BYTES_AVAILABLE(client, 2, goto fail_rollback);
        PACK_2B_INT(strlen(lwt->will_topic), frag);
        if (_optimized_add(client, lwt->will_topic, strlen(lwt->will_topic), lwt->will_topic_free, &frag))
            goto fail_rollback;

        // Will Payload [MQTT-3.1.3.4]
        if (lwt->will_message_size) {
            BUFFER_TRANSACTION_NEW_FRAG(client, 0, frag, goto fail_rollback);
            CHECK_BYTES_AVAILABLE(client, 2, goto fail_rollback);
            PACK_2B_INT(lwt->will_message_size, frag);
            if (_optimized_add(client, lwt->will_message, lwt->will_message_size, lwt->will_topic_free, &frag))
                goto fail_rollback;
        }
    }

    // [MQTT-3.1.3.5]
    if (auth->username) {
        BUFFER_TRANSACTION_NEW_FRAG(client, 0, frag, goto fail_rollback);
        CHECK_BYTES_AVAILABLE(client, 2, goto fail_rollback);
        PACK_2B_INT(strlen(auth->username), frag);
        if (_optimized_add(client, auth->username, strlen(auth->username), auth->username_free, &frag))
            goto fail_rollback;
    }

    // [MQTT-3.1.3.6]
    if (auth->password) {
        BUFFER_TRANSACTION_NEW_FRAG(client, 0, frag, goto fail_rollback);
        CHECK_BYTES_AVAILABLE(client, 2, goto fail_rollback);
        PACK_2B_INT(strlen(auth->password), frag);
        if (_optimized_add(client, auth->password, strlen(auth->password), auth->password_free, &frag))
            goto fail_rollback;
    }
    client->buf.tail_frag->flags |= BUFFER_FRAG_MQTT_PACKET_TAIL;
    buffer_transaction_commit(client);
    return ret;
fail_rollback:
    buffer_transaction_rollback(client, ret);
    return NULL;
}

int mqtt_ng_connect(struct mqtt_ng_client *client,
                    struct mqtt_auth_properties *auth,
                    struct mqtt_lwt_properties *lwt,
                    uint8_t clean_start,
                    uint16_t keep_alive)
{
    client->client_state = RAW;
/*  // this had issue when connection was dropped on network layer
    // mqtt client has no way of knowing about it yet
    // I might reconsider allowing this in future 
    if (client->client_state != RAW) {
        ERROR("Cannot connect already connected (or connecting) client");
        return 1;
    }*/
    client->connect_msg = mqtt_ng_generate_connect(client, auth, lwt, clean_start, keep_alive);
    if (client->connect_msg == NULL) {
        return 1;
    }

    client->client_state = CONNECT_PENDING;
    return 0;
}

uint16_t get_unused_packet_id() {
    static uint16_t packet_id = 0;
    packet_id++;
    return packet_id ? packet_id : ++packet_id;
}

static inline size_t mqtt_ng_publish_size(const char *topic,
                            size_t msg_len)
{
    return 2 /* Topic Name Length */
        + strlen(topic)
        + 2 /* Packet identifier */
        + 1 /* Properties Length TODO for now fixed 0 */
        + msg_len;
}

mqtt_msg_data mqtt_ng_generate_publish(struct mqtt_ng_client *client,
                                       const char *topic,
                                       free_fnc_t topic_free,
                                       const void *msg,
                                       free_fnc_t msg_free,
                                       size_t msg_len,
                                       uint8_t publish_flags,
                                       uint16_t *packet_id)
{
    // >> START THE RODEO <<
    buffer_transaction_start(client);

    // Calculate the resulting message size sans fixed MQTT header
    size_t size = mqtt_ng_publish_size(topic, msg_len);

    // Start generating the message
    struct buffer_fragment *frag = NULL;
    mqtt_msg_data ret = NULL;

    BUFFER_TRANSACTION_NEW_FRAG(client, BUFFER_FRAG_MQTT_PACKET_HEAD, frag, goto fail_rollback );
    ret = frag;

    // MQTT Fixed Header
    size_t needed_bytes = 1 /* Packet type */ + MQTT_VARSIZE_INT_BYTES(size) + size - msg_len;
    CHECK_BYTES_AVAILABLE(client, needed_bytes, goto fail_rollback);

    *WRITE_POS(frag) = (MQTT_CPT_PUBLISH << 4) | (publish_flags & 0xF);
    DATA_ADVANCE(1, frag);
    DATA_ADVANCE(uint32_to_mqtt_vbi(size, WRITE_POS(frag)), frag);

    // MQTT Variable Header
    // [MQTT-3.3.2.1]
    PACK_2B_INT(strlen(topic), frag);
    if (_optimized_add(client, topic, strlen(topic), topic_free, &frag))
        goto fail_rollback;
    BUFFER_TRANSACTION_NEW_FRAG(client, 0, frag, goto fail_rollback);

    // [MQTT-3.3.2.2]
    ret->packet_id = get_unused_packet_id();
    *packet_id = ret->packet_id;
    PACK_2B_INT(ret->packet_id, frag);

    // [MQTT-3.3.2.3.1] TODO Property Length for now fixed 0
    *WRITE_POS(frag) = 0;
    DATA_ADVANCE(1, frag);

    if( (frag = buffer_new_frag(client, BUFFER_FRAG_DATA_EXTERNAL)) == NULL ) {
        ERROR("Out of buffer space while generating the message");
        goto fail_rollback;
    }
    if (frag_set_external_data(client->log, frag, msg, msg_len, msg_free)) {
        ERROR("Error adding external data to newly created fragment");
        goto fail_rollback;
    }

    client->buf.tail_frag->flags |= BUFFER_FRAG_MQTT_PACKET_TAIL;
    buffer_transaction_commit(client);
    return ret;
fail_rollback:
    buffer_transaction_rollback(client, ret);
    return NULL;
}

int mqtt_ng_publish(struct mqtt_ng_client *client,
                    const char *topic,
                    free_fnc_t topic_free,
                    const void *msg,
                    free_fnc_t msg_free,
                    size_t msg_len,
                    uint8_t publish_flags,
                    uint16_t *packet_id)
{
    mqtt_msg_data generated = mqtt_ng_generate_publish(client, topic, topic_free, msg, msg_free, msg_len, publish_flags, packet_id);

    if (!generated)
        return 1;

    return 0;
}

static inline size_t mqtt_ng_subscribe_size(struct mqtt_sub *subs, size_t sub_count)
{
    size_t len = 2 /* Packet Identifier */ + 1 /* Properties Length TODO for now fixed 0 */;
    len += sub_count * (2 /* topic filter string length */ + 1 /* [MQTT-3.8.3.1] Subscription Options Byte */);

    for (size_t i = 0; i < sub_count; i++) {
        len += strlen(subs[i].topic);
    }
    return len;
}

mqtt_msg_data mqtt_ng_generate_subscribe(struct mqtt_ng_client *client, struct mqtt_sub *subs, size_t sub_count)
{
    // >> START THE RODEO <<
    buffer_transaction_start(client);

    // Calculate the resulting message size sans fixed MQTT header
    size_t size = mqtt_ng_subscribe_size(subs, sub_count);

    // Start generating the message
    struct buffer_fragment *frag = NULL;
    mqtt_msg_data ret = NULL;

    BUFFER_TRANSACTION_NEW_FRAG(client, BUFFER_FRAG_MQTT_PACKET_HEAD, frag, goto fail_rollback);
    ret = frag;

    // MQTT Fixed Header
    size_t needed_bytes = 1 /* Packet type */ + MQTT_VARSIZE_INT_BYTES(size) + 3 /*Packet ID + Property Length*/;
    CHECK_BYTES_AVAILABLE(client, needed_bytes, goto fail_rollback);

    *WRITE_POS(frag) = (MQTT_CPT_SUBSCRIBE << 4) | 0x2 /* [MQTT-3.8.1-1] */;
    DATA_ADVANCE(1, frag);
    DATA_ADVANCE(uint32_to_mqtt_vbi(size, WRITE_POS(frag)), frag);

    // MQTT Variable Header
    // [MQTT-3.8.2] PacketID
    ret->packet_id = get_unused_packet_id();
    PACK_2B_INT(ret->packet_id, frag);

    // [MQTT-3.8.2.1.1] Property Length // TODO for now fixed 0
    *WRITE_POS(frag) = 0;
    DATA_ADVANCE(1, frag);

    for (size_t i = 0; i < sub_count; i++) {
        BUFFER_TRANSACTION_NEW_FRAG(client, 0, frag, goto fail_rollback);
        PACK_2B_INT(strlen(subs[i].topic), frag);
        if (_optimized_add(client, subs[i].topic, strlen(subs[i].topic), subs[i].topic_free, &frag))
            goto fail_rollback;
        BUFFER_TRANSACTION_NEW_FRAG(client, 0, frag, goto fail_rollback);
        *WRITE_POS(frag) = subs[i].options;
        DATA_ADVANCE(1,frag);
    }

    client->buf.tail_frag->flags |= BUFFER_FRAG_MQTT_PACKET_TAIL;
    buffer_transaction_commit(client);
    return ret;
fail_rollback:
    buffer_transaction_rollback(client, ret);
    return NULL;
}

int mqtt_ng_subscribe(struct mqtt_ng_client *client, struct mqtt_sub *subs, size_t sub_count)
{
    mqtt_msg_data generated = mqtt_ng_generate_subscribe(client, subs, sub_count);

    if (!generated)
        return 1;

    return 0;
}

mqtt_msg_data mqtt_ng_generate_disconnect(struct mqtt_ng_client *client, uint8_t reason_code)
{
    // >> START THE RODEO <<
    buffer_transaction_start(client);

    // Calculate the resulting message size sans fixed MQTT header
    size_t size = reason_code ? 1 : 0;

    // Start generating the message
    struct buffer_fragment *frag = NULL;
    mqtt_msg_data ret = NULL;

    BUFFER_TRANSACTION_NEW_FRAG(client, BUFFER_FRAG_MQTT_PACKET_HEAD, frag, goto fail_rollback);
    ret = frag;

    // MQTT Fixed Header
    size_t needed_bytes = 1 /* Packet type */ + MQTT_VARSIZE_INT_BYTES(size) + (reason_code ? 1 : 0);
    CHECK_BYTES_AVAILABLE(client, needed_bytes, goto fail_rollback);

    *WRITE_POS(frag) = MQTT_CPT_DISCONNECT << 4;
    DATA_ADVANCE(1, frag);
    DATA_ADVANCE(uint32_to_mqtt_vbi(size, WRITE_POS(frag)), frag);

    if (reason_code) {
        // MQTT Variable Header
        // [MQTT-3.14.2.1] PacketID
        *WRITE_POS(frag) = reason_code;
        DATA_ADVANCE(1, frag);
    }

    client->buf.tail_frag->flags |= BUFFER_FRAG_MQTT_PACKET_TAIL;
    buffer_transaction_commit(client);
    return ret;
fail_rollback:
    buffer_transaction_rollback(client, ret);
    return NULL;
}

int mqtt_ng_disconnect(struct mqtt_ng_client *client, uint8_t reason_code)
{
    mqtt_msg_data generated = mqtt_ng_generate_disconnect(client, reason_code);

    if (!generated)
        return 1;

    return 0;
}

static int mqtt_generate_puback(struct mqtt_ng_client *client, uint16_t packet_id, uint8_t reason_code)
{
    // >> START THE RODEO <<
    buffer_transaction_start(client);

    // Calculate the resulting message size sans fixed MQTT header
    size_t size = 2 /* Packet ID */ + (reason_code ? 1 : 0) /* reason code */;

    // Start generating the message
    struct buffer_fragment *frag = NULL;

    BUFFER_TRANSACTION_NEW_FRAG(client, BUFFER_FRAG_MQTT_PACKET_HEAD | BUFFER_FRAG_GARBAGE_COLLECT_ON_SEND, frag, goto fail_rollback);

    // MQTT Fixed Header
    size_t needed_bytes = 1 /* Packet type */ + MQTT_VARSIZE_INT_BYTES(size) + size;
    CHECK_BYTES_AVAILABLE(client, needed_bytes, goto fail_rollback);

    *WRITE_POS(frag) = MQTT_CPT_PUBACK << 4;
    DATA_ADVANCE(1, frag);
    DATA_ADVANCE(uint32_to_mqtt_vbi(size, WRITE_POS(frag)), frag);

    // MQTT Variable Header
    PACK_2B_INT(packet_id, frag);

    if (reason_code) {
        // MQTT Variable Header
        // [MQTT-3.14.2.1] PacketID
        *WRITE_POS(frag) = reason_code;
        DATA_ADVANCE(1, frag);
    }

    client->buf.tail_frag->flags |= BUFFER_FRAG_MQTT_PACKET_TAIL;
    buffer_transaction_commit(client);
    return 0;
fail_rollback:
    buffer_transaction_rollback(client, frag);
    return 1;
}

static int mqtt_generate_pingreq(struct mqtt_ng_client *client)
{
    // >> START THE RODEO <<
    buffer_transaction_start(client);

    // Start generating the message
    struct buffer_fragment *frag = NULL;

    BUFFER_TRANSACTION_NEW_FRAG(client, BUFFER_FRAG_MQTT_PACKET_HEAD | BUFFER_FRAG_MQTT_PACKET_TAIL | BUFFER_FRAG_GARBAGE_COLLECT_ON_SEND, frag, goto fail_rollback);

    CHECK_BYTES_AVAILABLE(client, 2, goto fail_rollback);

    *WRITE_POS(frag) = MQTT_CPT_PINGREQ << 4;
    DATA_ADVANCE(1, frag);
    *WRITE_POS(frag) = 0;
    DATA_ADVANCE(1, frag);

    buffer_transaction_commit(client);
    return 0;
fail_rollback:
    buffer_transaction_rollback(client, frag);
    return 1;
}

int mqtt_ng_ping(struct mqtt_ng_client *client)
{
    return mqtt_generate_pingreq(client);
}

#define MQTT_NG_CLIENT_NEED_MORE_BYTES         0x10
#define MQTT_NG_CLIENT_MQTT_PACKET_DONE        0x11
#define MQTT_NG_CLIENT_PARSE_DONE              0x12
#define MQTT_NG_CLIENT_WANT_WRITE              0x13
#define MQTT_NG_CLIENT_OK_CALL_AGAIN           0
#define MQTT_NG_CLIENT_PROTOCOL_ERROR         -1
#define MQTT_NG_CLIENT_SERVER_RETURNED_ERROR  -2
#define MQTT_NG_CLIENT_NOT_IMPL_YET           -3
#define MQTT_NG_CLIENT_OOM                    -4

#define BUF_READ_CHECK_AT_LEAST(buf, x)                 \
    if (rbuf_bytes_available(buf) < (x)) \
        return MQTT_NG_CLIENT_NEED_MORE_BYTES;

#define vbi_parser_reset_ctx(ctx) memset(ctx, 0, sizeof(struct mqtt_vbi_parser_ctx))

static int vbi_parser_parse(struct mqtt_vbi_parser_ctx *ctx, rbuf_t data, mqtt_wss_log_ctx_t log)
{
    if (ctx->bytes > MQTT_VBI_MAXBYTES) {
        mws_error(log, "MQTT Variable Byte Integer can't be longer than %d bytes", MQTT_VBI_MAXBYTES);
        return MQTT_NG_CLIENT_PROTOCOL_ERROR;
    }
    if (!ctx->bytes || ctx->data[ctx->bytes-1] & MQTT_VBI_CONTINUATION_FLAG) {
        BUF_READ_CHECK_AT_LEAST(data, 1);
        ctx->bytes++;
        rbuf_pop(data, &ctx->data[ctx->bytes-1], 1);
        if ( ctx->data[ctx->bytes-1] & MQTT_VBI_CONTINUATION_FLAG )
            return MQTT_NG_CLIENT_NEED_MORE_BYTES;
    }

    if (mqtt_vbi_to_uint32(ctx->data, &ctx->result)) {
            mws_error(log, "MQTT Variable Byte Integer failed to be parsed.");
            return MQTT_NG_CLIENT_PROTOCOL_ERROR;
    }

    return MQTT_NG_CLIENT_PARSE_DONE;
}

static void mqtt_properties_parser_ctx_reset(struct mqtt_properties_parser_ctx *ctx)
{
    ctx->state = PROPERTIES_LENGTH;
    ctx->head = NULL;
    ctx->properties_length = 0;
    ctx->bytes_consumed = 0;
    vbi_parser_reset_ctx(&ctx->vbi_parser_ctx);
}

// Parses [MQTT-2.2.2]
static int parse_properties_array(struct mqtt_properties_parser_ctx *ctx, rbuf_t data, mqtt_wss_log_ctx_t log)
{
    int rc;
    switch (ctx->state) {
        case PROPERTIES_LENGTH:
            rc = vbi_parser_parse(&ctx->vbi_parser_ctx, data, log);
            if (rc == MQTT_NG_CLIENT_PARSE_DONE) {
                ctx->properties_length = ctx->vbi_parser_ctx.result;
                ctx->bytes_consumed += ctx->vbi_parser_ctx.bytes;
                if (!ctx->properties_length)
                    return MQTT_NG_CLIENT_PARSE_DONE;
                ctx->state = PROPERTY_ID;
                vbi_parser_reset_ctx(&ctx->vbi_parser_ctx);
                break;
            }
            return rc;
        case PROPERTY_ID:
            // TODO ignore for now... just skip
            rbuf_bump_tail(data, ctx->properties_length);
            ctx->bytes_consumed += ctx->properties_length;
            return MQTT_NG_CLIENT_PARSE_DONE;
//            rc = vbi_parser_parse(&ctx->vbi_parser_ctx, data, log);
    }
    return MQTT_NG_CLIENT_OK_CALL_AGAIN;
}

static int parse_connack_varhdr(struct mqtt_ng_client *client)
{
    struct mqtt_ng_parser *parser = &client->parser;
    switch (parser->varhdr_state) {
        case MQTT_PARSE_VARHDR_INITIAL:
            BUF_READ_CHECK_AT_LEAST(parser->received_data, 2);
            rbuf_pop(parser->received_data, (char*)&parser->mqtt_packet.connack.flags, 1);
            rbuf_pop(parser->received_data, (char*)&parser->mqtt_packet.connack.reason_code, 1);
            parser->varhdr_state = MQTT_PARSE_VARHDR_PROPS;
            mqtt_properties_parser_ctx_reset(&parser->properties_parser);
            break;
        case MQTT_PARSE_VARHDR_PROPS:
            return parse_properties_array(&parser->properties_parser, parser->received_data, client->log);
    }
    return MQTT_NG_CLIENT_OK_CALL_AGAIN;
}

static int parse_puback_varhdr(struct mqtt_ng_client *client)
{
    struct mqtt_ng_parser *parser = &client->parser;
    switch (parser->varhdr_state) {
        case MQTT_PARSE_VARHDR_INITIAL:
            BUF_READ_CHECK_AT_LEAST(parser->received_data, 2);
            rbuf_pop(parser->received_data, (char*)&parser->mqtt_packet.puback.packet_id, 2);
            parser->mqtt_packet.puback.packet_id = be16toh(parser->mqtt_packet.puback.packet_id);
            if (parser->mqtt_fixed_hdr_remaining_length < 3) {
                // [MQTT-3.4.2.1] if length is not big enough for reason code
                // it is omitted and handled same as if it was present and == 0
                // initially missed this detail and was wondering WTF is going on (sigh)
                parser->mqtt_packet.puback.reason_code = 0;
                return MQTT_NG_CLIENT_PARSE_DONE;
            }
            parser->varhdr_state = MQTT_PARSE_VARHDR_OPTIONAL_REASON_CODE;
            /* FALLTHROUGH */
        case MQTT_PARSE_VARHDR_OPTIONAL_REASON_CODE:
            BUF_READ_CHECK_AT_LEAST(parser->received_data, 1);
            rbuf_pop(parser->received_data, (char*)&parser->mqtt_packet.puback.reason_code, 1);
            // LOL so in CONNACK you have to have 0 byte to
            // signify empty properties list
            // but in PUBACK it can be omitted if remaining length doesn't allow it (sigh)
            if (parser->mqtt_fixed_hdr_remaining_length < 4)
                return MQTT_NG_CLIENT_PARSE_DONE;

            parser->varhdr_state = MQTT_PARSE_VARHDR_PROPS;
            mqtt_properties_parser_ctx_reset(&parser->properties_parser);
            /* FALLTHROUGH */
        case MQTT_PARSE_VARHDR_PROPS:
            return parse_properties_array(&parser->properties_parser, parser->received_data, client->log);
    }
    return MQTT_NG_CLIENT_OK_CALL_AGAIN;
}

static int parse_suback_varhdr(struct mqtt_ng_client *client)
{
    struct mqtt_ng_parser *parser = &client->parser;
    struct mqtt_suback *suback = &client->parser.mqtt_packet.suback;
    switch (parser->varhdr_state) {
        case MQTT_PARSE_VARHDR_INITIAL:
            BUF_READ_CHECK_AT_LEAST(parser->received_data, 2);
            rbuf_pop(parser->received_data, (char*)&suback->packet_id, 2);
            suback->packet_id = be16toh(suback->packet_id);
            parser->varhdr_state = MQTT_PARSE_VARHDR_PROPS;
            parser->mqtt_parsed_len = 2;
            mqtt_properties_parser_ctx_reset(&parser->properties_parser);
            /* FALLTHROUGH */
        case MQTT_PARSE_VARHDR_PROPS:
            int rc = parse_properties_array(&parser->properties_parser, parser->received_data, client->log);
            if (rc != MQTT_NG_CLIENT_PARSE_DONE) 
                return rc;
            parser->mqtt_parsed_len += parser->properties_parser.bytes_consumed;
            suback->reason_code_count = parser->mqtt_fixed_hdr_remaining_length - parser->mqtt_parsed_len;
            suback->reason_codes = calloc(suback->reason_code_count, sizeof(*suback->reason_codes));
            suback->reason_codes_pending = suback->reason_code_count;
            parser->varhdr_state = MQTT_PARSE_REASONCODES;
            /* FALLTROUGH */
        case MQTT_PARSE_REASONCODES:
            size_t avail = rbuf_bytes_available(parser->received_data);
            if (avail < 1)
                return MQTT_NG_CLIENT_NEED_MORE_BYTES;

            suback->reason_codes_pending -= rbuf_pop(parser->received_data, suback->reason_codes, MIN(suback->reason_codes_pending, avail));

            if (!suback->reason_codes_pending)
                return MQTT_NG_CLIENT_PARSE_DONE;

            return MQTT_NG_CLIENT_NEED_MORE_BYTES;
    }
    return MQTT_NG_CLIENT_OK_CALL_AGAIN;
}

static int parse_publish_varhdr(struct mqtt_ng_client *client)
{
    struct mqtt_ng_parser *parser = &client->parser;
    struct mqtt_publish *publish = &client->parser.mqtt_packet.publish;
    switch (parser->varhdr_state) {
        case MQTT_PARSE_VARHDR_INITIAL:
            BUF_READ_CHECK_AT_LEAST(parser->received_data, 2);
            publish->qos = ((parser->mqtt_control_packet_type >> 1) & 0x03);
            rbuf_pop(parser->received_data, (char*)&publish->topic_len, 2);
            publish->topic_len = be16toh(publish->topic_len);
            publish->topic = calloc(1, publish->topic_len + 1 /* add 0x00 */);
            if (publish->topic == NULL)
                return MQTT_NG_CLIENT_OOM;
            parser->varhdr_state = MQTT_PARSE_VARHDR_PACKET_ID;
            parser->mqtt_parsed_len = 2;
            /* FALLTHROUGH */
        case MQTT_PARSE_VARHDR_TOPICNAME:
            // TODO check empty topic can be valid? In which case we have to skip this step
            BUF_READ_CHECK_AT_LEAST(parser->received_data, publish->topic_len);
            rbuf_pop(parser->received_data, publish->topic, publish->topic_len);
            parser->mqtt_parsed_len += publish->topic_len;
            mqtt_properties_parser_ctx_reset(&parser->properties_parser);
            if (!publish->qos) { // PacketID present only for QOS > 0 [MQTT-3.3.2.2]
                parser->varhdr_state = MQTT_PARSE_VARHDR_PROPS;
                break;
            }
            parser->varhdr_state = MQTT_PARSE_VARHDR_PACKET_ID;
            /* FALLTHROUGH */
        case MQTT_PARSE_VARHDR_PACKET_ID:
            BUF_READ_CHECK_AT_LEAST(parser->received_data, 2);
            rbuf_pop(parser->received_data, (char*)&publish->packet_id, 2);
            publish->packet_id = be16toh(publish->packet_id);
            parser->varhdr_state = MQTT_PARSE_VARHDR_PROPS;
            parser->mqtt_parsed_len += 2;
            /* FALLTHROUGH */
        case MQTT_PARSE_VARHDR_PROPS:
            int rc = parse_properties_array(&parser->properties_parser, parser->received_data, client->log);
            if (rc != MQTT_NG_CLIENT_PARSE_DONE) 
                return rc;
            parser->mqtt_parsed_len += parser->properties_parser.bytes_consumed;
            parser->varhdr_state = MQTT_PARSE_PAYLOAD;
            /* FALLTROUGH */
        case MQTT_PARSE_PAYLOAD:
            if (parser->mqtt_fixed_hdr_remaining_length < parser->mqtt_parsed_len) {
                free(publish->topic);
                publish->topic = NULL;
                ERROR("Error parsing PUBLISH message");
                return MQTT_NG_CLIENT_PROTOCOL_ERROR;
            }
            publish->data_len = parser->mqtt_fixed_hdr_remaining_length - parser->mqtt_parsed_len;
            if (!publish->data_len) {
                publish->data = NULL;
                return MQTT_NG_CLIENT_PARSE_DONE; // 0 length payload is OK [MQTT-3.3.3]
            }
            BUF_READ_CHECK_AT_LEAST(parser->received_data, publish->data_len);

            publish->data = malloc(publish->data_len);
            if (publish->data == NULL) {
                free(publish->topic);
                publish->topic = NULL;
                return MQTT_NG_CLIENT_OOM;
            }

            rbuf_pop(parser->received_data, publish->data, publish->data_len);
            parser->mqtt_parsed_len += publish->data_len;

            return MQTT_NG_CLIENT_PARSE_DONE;
    }
    return MQTT_NG_CLIENT_OK_CALL_AGAIN;
}

// TODO move to separate file, dont send whole client pointer just to be able
// to access LOG context send parser only which should include log
static int parse_data(struct mqtt_ng_client *client)
{
    int rc;
    struct mqtt_ng_parser *parser = &client->parser;
    switch(parser->state) {
        case MQTT_PARSE_FIXED_HEADER_PACKET_TYPE:
            BUF_READ_CHECK_AT_LEAST(parser->received_data, 1);
            rbuf_pop(parser->received_data, (char*)&parser->mqtt_control_packet_type, 1);
            vbi_parser_reset_ctx(&parser->vbi_parser);
            parser->state = MQTT_PARSE_FIXED_HEADER_LEN;
            break;
        case MQTT_PARSE_FIXED_HEADER_LEN:
            int rc = vbi_parser_parse(&parser->vbi_parser, parser->received_data, client->log);
            if (rc == MQTT_NG_CLIENT_PARSE_DONE) {
                parser->mqtt_fixed_hdr_remaining_length = parser->vbi_parser.result;
                parser->state = MQTT_PARSE_VARIABLE_HEADER;
                parser->varhdr_state = MQTT_PARSE_VARHDR_INITIAL;
                break;
            }
            return rc;
        case MQTT_PARSE_VARIABLE_HEADER:
            switch (get_control_packet_type(parser->mqtt_control_packet_type)) {
                case MQTT_CPT_CONNACK:
                    rc = parse_connack_varhdr(client);
                    if (rc == MQTT_NG_CLIENT_PARSE_DONE) {
                        parser->state = MQTT_PARSE_MQTT_PACKET_DONE;
                        break;
                    }
                    return rc;
                case MQTT_CPT_PUBACK:
                    rc = parse_puback_varhdr(client);
                    if (rc == MQTT_NG_CLIENT_PARSE_DONE) {
                        parser->state = MQTT_PARSE_MQTT_PACKET_DONE;
                        break;
                    }
                    return rc;
                case MQTT_CPT_SUBACK:
                    rc = parse_suback_varhdr(client);
                    if (rc == MQTT_NG_CLIENT_PARSE_DONE) {
                        parser->state = MQTT_PARSE_MQTT_PACKET_DONE;
                        break;
                    }
                    return rc;
                case MQTT_CPT_PUBLISH:
                    rc = parse_publish_varhdr(client);
                    if (rc == MQTT_NG_CLIENT_PARSE_DONE) {
                        parser->state = MQTT_PARSE_MQTT_PACKET_DONE;
                        break;
                    }
                    return rc;
                case MQTT_CPT_PINGRESP:
                    if (parser->mqtt_fixed_hdr_remaining_length) {
                        ERROR ("PINGRESP has to be 0 Remaining Length."); // [MQTT-3.13.1]
                        return MQTT_NG_CLIENT_PROTOCOL_ERROR;
                    }
                    parser->state = MQTT_PARSE_MQTT_PACKET_DONE;
                    break;
                default:
                    ERROR("Parsing Control Packet Type %" PRIu8 " not implemented yet.", get_control_packet_type(parser->mqtt_control_packet_type));
                    rbuf_bump_tail(parser->received_data, parser->mqtt_fixed_hdr_remaining_length);
                    parser->state = MQTT_PARSE_MQTT_PACKET_DONE;
                    return MQTT_NG_CLIENT_NOT_IMPL_YET;
            }
            // we could also return MQTT_NG_CLIENT_OK_CALL_AGAIN
            // and be called again later
            /* FALLTHROUGH */
        case MQTT_PARSE_MQTT_PACKET_DONE:
            parser->state = MQTT_PARSE_FIXED_HEADER_PACKET_TYPE;
            return MQTT_NG_CLIENT_MQTT_PACKET_DONE;
    }
    return MQTT_NG_CLIENT_OK_CALL_AGAIN;
}

// set next MQTT message to send (pointer to first fragment)
// return 1 if nothing to send
// return -1 on error
// return 0 if there is fragment set
static int mqtt_ng_next_to_send(struct mqtt_ng_client *client) {
    if (client->client_state == CONNECT_PENDING) {
        client->sending_frag = client->connect_msg;
        client->client_state = CONNECTING;
        return 0;
    }
    if (client->client_state != CONNECTED)
        return -1;

    struct buffer_fragment *frag = BUFFER_FIRST_FRAG(&client->buf);
    while (frag) {
        if ( (frag->flags & BUFFER_FRAG_MQTT_PACKET_HEAD) && !frag->sent ) {
            client->sending_frag = client->sending_msg = frag;
            return 0;
        }
        frag = frag->next;
    }
    return 1;
}

// send current fragment
// return 0 if whole remaining length could be sent as a whole
// return -1 if send buffer was filled and
// nothing could be written anymore
// return 1 if last fragment of a message was fully sent
static int send_fragment(struct mqtt_ng_client *client) {
    struct buffer_fragment *frag = client->sending_frag;

    // for readability
    char *ptr = frag->data + frag->sent;
    size_t bytes = frag->len - frag->sent;

    size_t processed = 0;

    if (bytes)
        processed = client->send_fnc_ptr(client->user_ctx, ptr, bytes);
    else
        WARN("This fragment was fully sent already. This should not happen!");

    frag->sent += processed;
    if (frag->sent != frag->len)
        return -1;

    if (frag->flags & BUFFER_FRAG_MQTT_PACKET_TAIL) {
        client->time_of_last_send = time(NULL);
        client->sending_frag = NULL;
        return 1;
    }

    client->sending_frag = frag->next;
    
    return 0;
}

// attempt sending all fragments of current single MQTT packet
static int send_all_message_fragments(struct mqtt_ng_client *client) {
    int rc;
    while ( !(rc = send_fragment(client)) );
    return rc;
}

static void try_send_all(struct mqtt_ng_client *client) {
    do {
        if (client->sending_frag == NULL && mqtt_ng_next_to_send(client))
            return;
    } while(!send_all_message_fragments(client));
}

static inline void mark_message_for_gc(struct buffer_fragment *frag)
{
    while (frag) {
        frag->flags |= BUFFER_FRAG_GARBAGE_COLLECT;
        if (frag->flags & BUFFER_FRAG_MQTT_PACKET_TAIL)
            return;
        frag = frag->next;
    }
}

static int mark_packet_acked(struct mqtt_ng_client *client, uint16_t packet_id)
{
    struct buffer_fragment *frag = BUFFER_FIRST_FRAG(&client->buf);
    while (frag) {
        if ( (frag->flags & BUFFER_FRAG_MQTT_PACKET_HEAD) && frag->packet_id == packet_id) {
            if (!frag->sent) {
                ERROR("Received packet_id (%" PRIu16 ") belongs to MQTT packet which was not yet sent!", packet_id);
                return 1;
            }
            mark_message_for_gc(frag);
            return 0;
        }
        frag = frag->next;
    }
    ERROR("Received packet_id (%" PRIu16 ") is unknown!", packet_id);
    return 1;
}

int handle_incoming_traffic(struct mqtt_ng_client *client)
{
    int rc;
    while( (rc = parse_data(client)) == MQTT_NG_CLIENT_OK_CALL_AGAIN );
    if ( rc == MQTT_NG_CLIENT_MQTT_PACKET_DONE ) {
#ifdef MQTT_DEBUG_VERBOSE
        DEBUG("MQTT Packet Parsed Successfully!");
#endif
        switch (get_control_packet_type(client->parser.mqtt_control_packet_type)) {
            case MQTT_CPT_CONNACK:
#ifdef MQTT_DEBUG_VERBOSE
                DEBUG("Received CONNACK");
#endif
                mark_message_for_gc(client->connect_msg);
                client->connect_msg = NULL;
                if (client->client_state != CONNECTING) {
                    ERROR("Received unexpected CONNACK");
                    client->client_state = ERROR;
                    return MQTT_NG_CLIENT_PROTOCOL_ERROR;
                }
                if (client->connack_callback)
                    client->connack_callback(client->user_ctx, client->parser.mqtt_packet.connack.reason_code);
                if (!client->parser.mqtt_packet.connack.reason_code) {
                    INFO("MQTT Connection Accepted By Server");
                    client->client_state = CONNECTED;
                    break;
                }
                client->client_state = ERROR;
                return MQTT_NG_CLIENT_SERVER_RETURNED_ERROR;
            case MQTT_CPT_PUBACK:
#ifdef MQTT_DEBUG_VERBOSE
                DEBUG("Received PUBACK %" PRIu16, client->parser.mqtt_packet.puback.packet_id);
#endif
                if (mark_packet_acked(client, client->parser.mqtt_packet.puback.packet_id))
                    return MQTT_NG_CLIENT_PROTOCOL_ERROR;
                if (client->puback_callback)
                    client->puback_callback(client->parser.mqtt_packet.puback.packet_id);
                break;
            case MQTT_CPT_PINGRESP:
#ifdef MQTT_DEBUG_VERBOSE
                DEBUG("Received PINGRESP");
#endif
                break;
            case MQTT_CPT_SUBACK:
#ifdef MQTT_DEBUG_VERBOSE
                DEBUG("Received SUBACK %" PRIu16, client->parser.mqtt_packet.suback.packet_id);
#endif
                if (mark_packet_acked(client, client->parser.mqtt_packet.suback.packet_id))
                    return MQTT_NG_CLIENT_PROTOCOL_ERROR;
                break;
            case MQTT_CPT_PUBLISH:
#ifdef MQTT_DEBUG_VERBOSE
                DEBUG("Recevied PUBLISH");
#endif
                struct mqtt_publish *pub = &client->parser.mqtt_packet.publish;
                if (pub->qos > 1) {
                    free(pub->topic);
                    free(pub->data);
                    return MQTT_NG_CLIENT_NOT_IMPL_YET;
                }
                if (mqtt_generate_puback(client, pub->packet_id, 0)) {
                    ERROR("Error generating PUBACK reply for PUBLISH");
                    break;
                }
                if (client->msg_callback)
                    client->msg_callback(pub->topic, pub->data, pub->data_len, pub->qos);
                free(pub->topic);
                free(pub->data);
                return MQTT_NG_CLIENT_WANT_WRITE;
        }
    }

    return rc;
}

int mqtt_ng_sync(struct mqtt_ng_client *client)
{
    if (client->client_state == RAW)
        return 0;

    LOCK_HDR_BUFFER(client);
    try_send_all(client);
    UNLOCK_HDR_BUFFER(client);

    int ac = handle_incoming_traffic(client);
    // TODO this is quick and dirty
    if (ac != MQTT_NG_CLIENT_NEED_MORE_BYTES) {
        int ac = handle_incoming_traffic(client);
    }
    if (ac == MQTT_NG_CLIENT_WANT_WRITE) {
        LOCK_HDR_BUFFER(client);
        try_send_all(client);
        UNLOCK_HDR_BUFFER(client);
    }

    return 0;
}

time_t mqtt_ng_last_send_time(struct mqtt_ng_client *client)
{
    return client->time_of_last_send;
}
