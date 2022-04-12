#include <stdint.h>

#include "common_internal.h"



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

int mqtt_ng_init() {
    return 0;
}