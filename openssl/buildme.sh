#!/bin/bash
# openssl 1.1.1d buildme.sh
#
# (1) download openssl-1.1.1d.tar.gz from
#     https://www.openssl.org/source/old/1.1.1/openssl-1.1.1d.tar.gz
# (2) run this buildme.sh
#
OPENSSL_VER="openssl-1.1.1d"

echo "build and install ${OPENSSL_VER}"

if [ ! -f ${OPENSSL_VER}.tar.gz ]; then
  echo "Found no ${OPENSSL_VER}.tar.gz"
  echo "Please download it from "
  echo "  https://www.openssl.org/source/old/1.1.1/openssl-1.1.1d.tar.gz"
  exit 1
fi

INSTALL_PREFIX="$(dirname "$(pwd)")/local"

if [ -d ${OPENSSL_VER} ]; then
  rm -r ${OPENSSL_VER}
fi

tar -xf ${OPENSSL_VER}.tar.gz
if [ "$?" != "0" ]; then 
  exit 1
fi

cd ${OPENSSL_VER}

./config --prefix="${INSTALL_PREFIX}" no-shared no-tests no-engine

# make install_sw to bypass installing manpage
make install_sw

cd ..

# cleanup
rm -r ${OPENSSL_VER}

echo "${OPENSSL_VER} installed!"
