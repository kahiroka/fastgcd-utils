#!/bin/sh
# ./fastgcd.sh PATH_TO_MODULI

docker run --rm -it \
        --name=fastgcd \
        -e INPUT_MODULI=`readlink -f $1` \
        -v /home/${USER}:/home/${USER} \
        fastgcd/docker

