#!/bin/bash

BOARD=esp8266:esp8266:d1_mini_pro
USB0=/dev/ttyUSB0
USB1=/dev/ttyUSB1
AUNITER=../../AUniter

set -e

arduino-cli compile -v -e -b ${BOARD} HwUpdater
arduino-cli upload -b ${BOARD} -p ${USB0} -i HwUpdater/build/esp8266.esp8266.d1_mini_pro/HwUpdater.ino.bin &
arduino-cli upload -b ${BOARD} -p ${USB1} -i HwUpdater/build/esp8266.esp8266.d1_mini_pro/HwUpdater.ino.bin &
wait

echo 'Firmware upgraded'

# ${AUNITER}/tools/serial_monitor.py --port /dev/ttyUSB0 --baud 76800 --monitor | tee upgrader.log &
#${AUNITER}/tools/serial_monitor.py --port /dev/ttyUSB1 --baud 76800 --monitor | tee upgradee.log &
