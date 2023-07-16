#!/bin/bash

adb devices | grep "device$"

if [ $? -eq 0 ]; then
    echo "ADB is connected."
else
    echo "ADB is not connected."
fi
