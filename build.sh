#!/bin/sh

cd -- "$(dirname -- "$0")"

sodium_dir=`pwd`/../opt

exec gcc -I "$sodium_dir/include" -L "$sodium_dir/lib" -l sodium dpad.c -o dpad
