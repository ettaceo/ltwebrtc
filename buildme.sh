#!/bin/bash
# ltwebrtc/buildme.sh

BUILD=debug

if [ $# == 0 ]; then
  echo "Run with --release for release build"
  sleep 2
fi  

# check arguments 
for arg in "$@" ; do
  if [ "$arg" = "--release" ]; then
    BUILD=release
  fi
done

if [ ! -d "local" ]; then
  mkdir local
  if [ "$?" != "0" ]; then 
     echo "unable to create directory local"
     exit 1
  fi
fi

if [ ! -d "local/lib" ]; then
  mkdir local/lib
  if [ "$?" != "0" ]; then 
     echo "unable to create directory local/lib"
     exit 1
  fi
fi

if [ ! -d "local/include" ]; then
  mkdir local/include
  if [ "$?" != "0" ]; then 
     echo "unable to create directory local/include"
     exit 1
  fi
fi

# openssl
if [ ! -d "local/include/openssl" ]; then
  cd openssl
  bash buildme.sh
  if [ "$?" != "0" ]; then
    exit 1
  fi
  cd ..
fi

# cryptlib
if [ ! -d "local/include/cryptlib" ]; then
  mkdir local/include/cryptlib
  if [ "$?" != "0" ]; then 
     echo "unable to create directory local/include/cryptlib"
     exit 1
  fi
fi
make BUILD=${BUILD} -C cryptlib -f cryptlib.mk
if [ "$?" != "0" ]; then 
  echo "error make cryptlib"
  exit 1
fi
cp cryptlib/cryptlib.a local/lib
cp cryptlib/*.h local/include/cryptlib
make BUILD=${BUILD} -C cryptlib -f cryptlib.mk clean

# ts-demux
if [ ! -d "local/include/ts-demux" ]; then
  mkdir local/include/ts-demux
  if [ "$?" != "0" ]; then 
     echo "unable to create directory local/include/ts-demux"
     exit 1
  fi
fi
make BUILD=${BUILD} -C ts-demux -f ts-demux.mk
if [ "$?" != "0" ]; then 
  echo "error make ts-demux"
  exit 1
fi
cp ts-demux/ts-demux.a local/lib
cp ts-demux/*.h local/include/ts-demux
make BUILD=${BUILD} -C ts-demux -f ts-demux.mk clean

# iceagent
make BUILD=${BUILD} -C iceagent
if [ ! -d "export" ]; then
  mkdir export
  if [ "$?" != "0" ]; then 
     echo "unable to create directory export"
     exit 1
  fi
fi

# export
if [ ! -d "export" ]; then
  mkdir export
  if [ "$?" != "0" ]; then 
     echo "unable to create directory export"
     exit 1
  fi
fi
cp iceagent/iceagent export/
cp jsep/jsep.html export/jsep.html
cp jsep/jsep.js export/jsep.js
cp mediasrc/demo.mp4 export/demo.mp4

make -C iceagent clean
