#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

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

#define LOCK_HDR_BUFFER(client) pthread_mutex_lock(&client->buf_mutex)
#define UNLOCK_HDR_BUFFER(client) pthread_mutex_unlock(&client->buf_mutex)

#define BUFFER_FRAG_GARBAGE_COLLECT   0x01
// as buffer fragment can point to both
// external data and data in the same buffer
// we mark the former case with BUFFER_FRAG_DATA_EXTERNAL
#define BUFFER_FRAG_DATA_EXTERNAL     0x02
// as single MQTT Packet can be stored into multiple
// buffer fragments (depending on copy requirements)
// this marks this fragment to be the first/last
#define BUFFER_FRAG_MQTT_PACKET_HEAD  0x04
#define BUFFER_FRAG_MQTT_PACKET_TAIL  0x08

typedef uint16_t buffer_frag_flag_t;
struct buffer_fragment {
    size_t len;
    size_t sent;
    buffer_frag_flag_t flags;
    void (*free_fnc)(void *ptr);
    char *data;

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
    CONNECTED
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

    rbuf_t received_data;
    mqtt_ng_send_fnc_t send_fnc_ptr;
    void *user_ctx;

    struct buffer_fragment *sending_frag;
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
        output[i-1] = input & 0x7F;
        input >>= 7;
        if (input)
            output[i-1] |= 0x80;
        i++;
    }
    return i - 1;
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
#endif /* TESTS */

#define HEADER_BUFFER_SIZE 1024*1024
struct mqtt_ng_client *mqtt_ng_init(mqtt_wss_log_ctx_t log, rbuf_t data_in, mqtt_ng_send_fnc_t send_fnc, void *user_ctx) {
    struct mqtt_ng_client *client = calloc(1, sizeof(struct mqtt_ng_client) + HEADER_BUFFER_SIZE);
    if (client == NULL)
        return NULL;

    pthread_mutex_init(&client->buf_mutex, NULL);

    client->buf.buffer_size = HEADER_BUFFER_SIZE;
    client->buf.data = ((char*)client) + sizeof(struct mqtt_ng_client);
    client->buf.tail = client->buf.data;
    client->buf.tail_frag = NULL;

    client->received_data = data_in;
    client->send_fnc_ptr = send_fnc;
    client->user_ctx = user_ctx;

    client->log = log;

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

#define BUFFER_BYTES_USED(buf) ((size_t)((buf)->tail - (buf)->data))
#define BUFFER_BYTES_AVAILABLE(buf) (HEADER_BUFFER_SIZE - BUFFER_BYTES_USED(buf))

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
    uint32_t a;
    printf("Data %d, LEn fnc %d, Len macro %d\n", size, uint32_to_mqtt_vbi(size, &a), MQTT_VARSIZE_INT_BYTES(size));
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
    BUFFER_TRANSACTION_NEW_FRAG(client, 0, frag, goto fail_rollback);

    if (lwt != NULL) {
        // Will Properties [MQTT-3.1.3.2]
        // TODO for now fixed 0
        CHECK_BYTES_AVAILABLE(client, 1, goto fail_rollback);
        *WRITE_POS(frag) = 0;
        DATA_ADVANCE(1, frag);

        // Will Topic [MQTT-3.1.3.3]
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
    if (client->client_state != RAW) {
        ERROR("Cannot connect already connected (or connecting) client");
        return 1;
    }
    client->connect_msg = mqtt_ng_generate_connect(client, auth, lwt, clean_start, keep_alive);
    if (client->connect_msg == NULL) {
        return 1;
    }

        dump_buffer_fragment(client->connect_msg);

    client->client_state = CONNECT_PENDING;
    return 0;
}

//    dump_buffer_fragment(client->buf.data);

// this dummy exists to have a special pointer with special meaning
// other than NULL
void _caller_responsibility(void *ptr) {
    (void)(ptr);
}

// set next MQTT message to send (pointer to first fragment)
// return 1 if nothing to send
// return 0 if there is fragment set
static int mqtt_ng_next_to_send(struct mqtt_ng_client *client) {
    if (client->client_state == CONNECT_PENDING) {
        client->sending_frag = client->connect_msg;
        client->client_state = CONNECTING;
        return 0;
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

    size_t processed = client->send_fnc_ptr(client->user_ctx, ptr, bytes);

    frag->sent += processed;
    if (frag->sent != frag->len)
        return -1;

    if (frag->flags & BUFFER_FRAG_MQTT_PACKET_TAIL) {
        client->sending_frag = NULL;
        return 1;
    }

    client->sending_frag = frag->next;
    
    return 0;
}

// attempt sending all fragments of current MQTT packet
static int send_fragments(struct mqtt_ng_client *client) {
    int rc;
    while ( !(rc = send_fragment(client)) );
    return 1;
}

static void try_send_all(struct mqtt_ng_client *client) {
    while (client->sending_frag || !mqtt_ng_next_to_send(client)) {
        send_fragments(client);
    }
}

int mqtt_ng_sync(struct mqtt_ng_client *client) {
    if (client->client_state == RAW)
        return 0;
    try_send_all(client);
    ERROR("RCVD: %d", rbuf_bytes_available(client->received_data));
    return 0;
}
