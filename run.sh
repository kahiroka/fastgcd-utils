#!/bin/sh

cd /root/fastgcd 
./fastgcd $INPUT_MODULI
cp vulnerable_moduli `dirname $INPUT_MODULI`
cp gcds `dirname $INPUT_MODULI`
