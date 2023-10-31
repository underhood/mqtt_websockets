# mqtt_websockets

Library to connect MQTT client over Websockets Secure (WSS).
Documentation is pending. Best way to figure out how to use the library it to look at [`netdata/netdata`](https://github.com/netdata/netdata/) where it is used in production (ACLK component used for Cloud/Agent communication) and/or `src\test.c`.

## License

The Project is released under GPL v3 license. See [License](LICENSE)

Uses following git submodules:
- **c-rbuf**: under LGPL 3 by underhood
- **c_rhash**: GPL 3 by underhood
