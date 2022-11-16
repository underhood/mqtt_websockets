#include "mqtt_wss_log.h"
#include "include/mqtt_ng.h"

#include <stdio.h>
unsigned char reconstructed_packet_bin[] = {
  0x30, 0xff, 0x05, 0x00, 0x37, 0x2f, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2f,
  0x36, 0x35, 0x66, 0x62, 0x37, 0x35, 0x63, 0x32, 0x2d, 0x36, 0x31, 0x65,
  0x38, 0x2d, 0x31, 0x31, 0x65, 0x64, 0x2d, 0x61, 0x37, 0x36, 0x61, 0x2d,
  0x62, 0x32, 0x38, 0x35, 0x61, 0x33, 0x65, 0x36, 0x65, 0x33, 0x36, 0x31,
  0x2f, 0x69, 0x6e, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x2f, 0x63, 0x6d, 0x64,
  0x00, 0x7b, 0x22, 0x74, 0x79, 0x70, 0x65, 0x22, 0x3a, 0x22, 0x68, 0x74,
  0x74, 0x70, 0x22, 0x2c, 0x22, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
  0x22, 0x3a, 0x32, 0x2c, 0x22, 0x63, 0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63,
  0x6b, 0x2d, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x22, 0x3a, 0x22, 0x2f, 0x73,
  0x76, 0x63, 0x2f, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2d, 0x64, 0x61, 0x74,
  0x61, 0x2d, 0x63, 0x74, 0x72, 0x6c, 0x2f, 0x65, 0x30, 0x36, 0x31, 0x61,
  0x36, 0x32, 0x39, 0x2d, 0x62, 0x37, 0x34, 0x64, 0x2d, 0x34, 0x39, 0x30,
  0x36, 0x2d, 0x62, 0x37, 0x66, 0x38, 0x2d, 0x33, 0x36, 0x66, 0x37, 0x38,
  0x64, 0x32, 0x36, 0x34, 0x63, 0x35, 0x36, 0x66, 0x32, 0x38, 0x66, 0x33,
  0x31, 0x64, 0x30, 0x2d, 0x38, 0x65, 0x39, 0x33, 0x2d, 0x34, 0x33, 0x66,
  0x31, 0x2d, 0x62, 0x36, 0x33, 0x33, 0x2d, 0x37, 0x30, 0x66, 0x39, 0x31,
  0x64, 0x31, 0x39, 0x35, 0x35, 0x36, 0x34, 0x22, 0x2c, 0x22, 0x6d, 0x73,
  0x67, 0x2d, 0x69, 0x64, 0x22, 0x3a, 0x22, 0x36, 0x35, 0x66, 0x62, 0x37,
  0x35, 0x63, 0x32, 0x2d, 0x36, 0x31, 0x65, 0x38, 0x2d, 0x31, 0x31, 0x65,
  0x64, 0x2d, 0x61, 0x37, 0x36, 0x61, 0x2d, 0x62, 0x32, 0x38, 0x35, 0x61,
  0x33, 0x65, 0x36, 0x65, 0x33, 0x36, 0x31, 0x2f, 0x61, 0x36, 0x63, 0x37,
  0x64, 0x65, 0x65, 0x31, 0x2d, 0x63, 0x39, 0x64, 0x35, 0x2d, 0x34, 0x36,
  0x33, 0x35, 0x2d, 0x38, 0x66, 0x39, 0x66, 0x2d, 0x36, 0x64, 0x61, 0x64,
  0x37, 0x62, 0x63, 0x38, 0x38, 0x30, 0x31, 0x61, 0x2f, 0x64, 0x61, 0x74,
  0x61, 0x2f, 0x31, 0x36, 0x36, 0x38, 0x35, 0x37, 0x38, 0x32, 0x34, 0x31,
  0x31, 0x39, 0x39, 0x34, 0x37, 0x34, 0x31, 0x31, 0x30, 0x22, 0x2c, 0x22,
  0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x22, 0x3a, 0x39, 0x30, 0x30,
  0x30, 0x7d, 0x0d, 0x0a, 0x0d, 0x0a, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x6e,
  0x6f, 0x64, 0x65, 0x2f, 0x62, 0x30, 0x63, 0x61, 0x38, 0x36, 0x62, 0x34,
  0x2d, 0x33, 0x39, 0x36, 0x36, 0x2d, 0x34, 0x62, 0x64, 0x66, 0x2d, 0x38,
  0x36, 0x61, 0x63, 0x2d, 0x63, 0x61, 0x65, 0x33, 0x61, 0x65, 0x65, 0x38,
  0x33, 0x30, 0x34, 0x30, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x31, 0x2f,
  0x64, 0x61, 0x74, 0x61, 0x3f, 0x61, 0x66, 0x74, 0x65, 0x72, 0x3d, 0x31,
  0x36, 0x36, 0x38, 0x35, 0x37, 0x37, 0x33, 0x34, 0x31, 0x26, 0x62, 0x65,
  0x66, 0x6f, 0x72, 0x65, 0x3d, 0x31, 0x36, 0x36, 0x38, 0x35, 0x37, 0x38,
  0x32, 0x34, 0x31, 0x26, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x3d,
  0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2e, 0x69, 0x6f, 0x26, 0x64, 0x69,
  0x6d, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x3d, 0x69, 0x6e, 0x26,
  0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x3d, 0x6a, 0x73, 0x6f, 0x6e, 0x26,
  0x67, 0x72, 0x6f, 0x75, 0x70, 0x3d, 0x61, 0x76, 0x65, 0x72, 0x61, 0x67,
  0x65, 0x26, 0x67, 0x74, 0x69, 0x6d, 0x65, 0x3d, 0x30, 0x26, 0x6f, 0x70,
  0x74, 0x69, 0x6f, 0x6e, 0x73, 0x3d, 0x61, 0x62, 0x73, 0x6f, 0x6c, 0x75,
  0x74, 0x65, 0x25, 0x37, 0x43, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x5f, 0x70,
  0x61, 0x73, 0x74, 0x25, 0x37, 0x43, 0x66, 0x6c, 0x69, 0x70, 0x25, 0x37,
  0x43, 0x6a, 0x73, 0x6f, 0x6e, 0x77, 0x72, 0x61, 0x70, 0x25, 0x37, 0x43,
  0x6d, 0x73, 0x26, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x73, 0x3d, 0x35, 0x32,
  0x37, 0x26, 0x73, 0x68, 0x6f, 0x77, 0x5f, 0x64, 0x69, 0x6d, 0x65, 0x6e,
  0x73, 0x69, 0x6f, 0x6e, 0x73, 0x3d, 0x31, 0x26, 0x74, 0x69, 0x6d, 0x65,
  0x6f, 0x75, 0x74, 0x3d, 0x39, 0x30, 0x30, 0x30, 0x20, 0x48, 0x54, 0x54,
  0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a,
  0x20, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2d, 0x61, 0x67, 0x65, 0x6e, 0x74,
  0x2d, 0x64, 0x61, 0x74, 0x61, 0x2d, 0x63, 0x74, 0x72, 0x6c, 0x2d, 0x73,
  0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x61, 0x70, 0x70, 0x0d, 0x0a,
  0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x45, 0x6e, 0x63, 0x6f, 0x64,
  0x69, 0x6e, 0x67, 0x3a, 0x20, 0x67, 0x7a, 0x69, 0x70, 0x0d, 0x0a, 0x4d,
  0x71, 0x74, 0x74, 0x2d, 0x42, 0x72, 0x6f, 0x6b, 0x65, 0x72, 0x2d, 0x41,
  0x64, 0x64, 0x72, 0x3a, 0x20, 0x65, 0x6d, 0x71, 0x78, 0x2e, 0x69, 0x6e,
  0x66, 0x72, 0x61, 0x3a, 0x31, 0x38, 0x38, 0x33, 0x0d, 0x0a, 0x4e, 0x65,
  0x74, 0x64, 0x61, 0x74, 0x61, 0x2d, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
  0x74, 0x2d, 0x49, 0x64, 0x3a, 0x20, 0x41, 0x65, 0x58, 0x41, 0x62, 0x34,
  0x50, 0x4d, 0x50, 0x76, 0x2d, 0x35, 0x35, 0x36, 0x34, 0x37, 0x39, 0x38,
  0x37, 0x37, 0x0d, 0x0a, 0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65,
  0x6e, 0x74, 0x3a, 0x20, 0x47, 0x6f, 0x2d, 0x68, 0x74, 0x74, 0x70, 0x2d,
  0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a,
  0x0d, 0x0a
};
unsigned int reconstructed_packet_bin_len = 770;


#define MQTT_NG_CLIENT_NEED_MORE_BYTES         0x10
#define MQTT_NG_CLIENT_MQTT_PACKET_DONE        0x11
#define MQTT_NG_CLIENT_PARSE_DONE              0x12
#define MQTT_NG_CLIENT_WANT_WRITE              0x13
#define MQTT_NG_CLIENT_OK_CALL_AGAIN           0
#define MQTT_NG_CLIENT_PROTOCOL_ERROR         -1
#define MQTT_NG_CLIENT_SERVER_RETURNED_ERROR  -2
#define MQTT_NG_CLIENT_NOT_IMPL_YET           -3
#define MQTT_NG_CLIENT_OOM                    -4
#define MQTT_NG_CLIENT_INTERNAL_ERROR         -5

int parse_data(struct mqtt_ng_client *client);
void hexdump_log(struct mqtt_ng_client *client, const char* data, size_t len, size_t bytes_per_line);

int main() {
    rbuf_t buf = rbuf_create(770*2.1);
    struct mqtt_ng_init init = {
        .log = NULL,
        .data_in = buf,
        .data_out_fnc = NULL,
        .user_ctx = NULL,
        .puback_callback = NULL,
        .connack_callback = NULL,
        .msg_callback = NULL
    };

    rbuf_push(buf, (char*)reconstructed_packet_bin, reconstructed_packet_bin_len);
    rbuf_bump_tail(buf, 770);
    rbuf_push(buf, (char*)reconstructed_packet_bin, reconstructed_packet_bin_len);
    rbuf_push(buf, (char*)reconstructed_packet_bin, reconstructed_packet_bin_len);

    struct mqtt_ng_client *client = mqtt_ng_init(&init);
    int rc;
    size_t avail = rbuf_bytes_available(buf);
    printf("start remaining:%d\n", (int)avail);
    while( (rc = parse_data(client)) == MQTT_NG_CLIENT_OK_CALL_AGAIN );
    avail = rbuf_bytes_available(buf);
    printf("%d remaining:%d\n", rc, (int)avail);
    while( (rc = parse_data(client)) == MQTT_NG_CLIENT_OK_CALL_AGAIN );
    avail = rbuf_bytes_available(buf);
    printf("%d remaining:%d\n", rc, (int)avail);

    rbuf_push(buf, (char*)reconstructed_packet_bin, reconstructed_packet_bin_len);
    while( (rc = parse_data(client)) == MQTT_NG_CLIENT_OK_CALL_AGAIN );
    avail = rbuf_bytes_available(buf);
    printf("%d remaining:%d\n", rc, (int)avail);
}