FROM fedora:latest

RUN dnf -y update
RUN dnf -y install automake autoconf gcc mosquitto
