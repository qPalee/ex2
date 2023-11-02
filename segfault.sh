#!/bin/sh

#globals
PORT=2223

./client localhost $PORT a 123.45.67.89 3074
./client localhost $PORT a 123.45.67.89 3075
./client localhost $PORT c 123.45.67.89 3074
./client localhost $PORT l
