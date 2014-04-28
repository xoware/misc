#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd ${DIR}

./sam-ba /dev/ttyACM0  at91sama5d3x-ek exokey_main.tcl

