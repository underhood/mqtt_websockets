#!/usr/bin/env bash

autoreconf -ivf
cd build
../configure
make
