# Fastgcd Utilities

This project contains a script which extracts n from RSA public key files and Dockerfile for fastgcd. Refer to https://factorable.net/index.html about fastgcd.

# Build

Build your fastgcd container.

    $ docker build -t fastgcd/docker .

# Usage

Put all RSA public key files in a directory and extract n from them, then run fastgcd. Supported files are PGP, X.509 certificate, RSA public key and SSH in PEM format.

    $ python3 ./extract.py keydir/ > moduli
    $ ./fastgcd.sh moduli

Result files are copyed on the host.

    vulnerable_moduli
    gcds
