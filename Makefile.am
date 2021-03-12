lib_LIBRARIES = libmqttwebsockets.a
noinst_PROGRAMS = test

mqtt3_FILES = \
    MQTT-C/src/mqtt.c \
    MQTT-C/include/mqtt.h \
    $(NULL)

crbuf_FILES = \
    c-rbuf/src/ringbuffer.c \
    c-rbuf/src/ringbuffer_internal.h \
    c-rbuf/include/ringbuffer.h \
    $(NULL)

libmqttwebsockets_a_SOURCES = \
    src/mqtt_wss_client.c \
    src/include/mqtt_wss_client.h \
    src/mqtt_wss_log.c \
    src/include/mqtt_wss_log.h \
    src/ws_client.c \
    src/include/ws_client.h \
    $(NULL)

libmqttwebsockets_a_CFLAGS = -I$(srcdir)/src/include -I$(srcdir)/MQTT-C/include -I$(srcdir)/c-rbuf/include

libmqttwebsockets_a_SOURCES += $(mqtt3_FILES) $(crbuf_FILES)

test_LDADD = \
    libmqttwebsockets.a \
    $(SSL_LIBS) \
    $(NULL)

test_SOURCES = \
    src/test.c \
    $(NULL)

test_CFLAGS = -I$(srcdir)/src/include
