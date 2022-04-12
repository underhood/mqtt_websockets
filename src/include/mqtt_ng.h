#include <stdint.h>

struct mqtt_ng_client {

};

struct mqtt_connect {
    
};

/* Converts integer to MQTT Variable Byte Integer as per 1.5.5 of MQTT 5 specs
 * @param input value to be converted
 * @param output pointer to memory where output will be written to. Must allow up to 4 bytes to be written.
 * @return number of bytes written to output or <= 0 if error in which case contents of output are undefined
 */
int uint32_to_mqtt_vbi(uint32_t input, char *output);

int mqtt_ng_init();