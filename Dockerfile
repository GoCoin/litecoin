FROM myvbo/cloudserver-48.153
MAINTAINER Scott Spangenberg
RUN sudo apt-get update

#WORKDIR /home/myvbo/cloudwallets/primecoin/src
#RUN make -f makefile.unix clean
#RUN make -f makefile.unix STATIC=1 RELEASE=1 64BIT=1 USE_QRCODE=1 USE_UPNP=1 DEPSDIR=/usr/local
#RUN make -f makefile.unix STATIC=1 RELEASE=1 64BIT=1 USE_QRCODE=1 USE_UPNP=1 DEPSDIR=/usr/local test
# primecoin/src/test_primecoin

#WORKDIR /home/myvbo/cloudwallets/peercoin/src
#RUN make -f makefile.unix clean
#RUN make -f makefile.unix STATIC=1 RELEASE=1 64BIT=1 USE_QRCODE=1 USE_UPNP=1 DEPSDIR=/usr/local
# Need to create make files to create and run the unit tests

#WORKDIR /home/myvbo/cloudwallets/peerunity/src
#RUN make -f makefile.unix clean
#RUN make -f makefile.unix STATIC=1 RELEASE=1 64BIT=1 USE_QRCODE=1 USE_UPNP=1 DEPSDIR=/usr/local
#RUN make -f makefile.unix STATIC=1 RELEASE=1 64BIT=1 USE_QRCODE=1 USE_UPNP=1 DEPSDIR=/usr/local test_peerunity

ADD . /home/myvbo/cloudwallets/litecoin
WORKDIR /home/myvbo/cloudwallets/litecoin/src
RUN make -f makefile.unix clean
RUN make -f makefile.unix STATIC=1 RELEASE=1 64BIT=1 USE_QRCODE=1 USE_UPNP=1 BDB_INCLUDE_PATH=/home/myvbo/cloudwallets/db-4.8.30/build_unix/ BDB_LIB_PATH=/usr/local/BerkeleyDB.4.8/lib BOOST_INCLUDE_PATH=/usr/local/boost1.53.0/include BOOST_LIB_PATH=/usr/local/boost1.53.0/lib
RUN make -f makefile.unix STATIC=1 RELEASE=1 64BIT=1 USE_QRCODE=1 USE_UPNP=1 BDB_INCLUDE_PATH=/home/myvbo/cloudwallets/db-4.8.30/build_unix/ BDB_LIB_PATH=/usr/local/BerkeleyDB.4.8/lib BOOST_INCLUDE_PATH=/usr/local/boost1.53.0/include BOOST_LIB_PATH=/usr/local/boost1.53.0/lib test

#WORKDIR /home/myvbo/cloudwallets/bitcoin
# create the make and config files appropriate for this environment
#RUN ./autogen.sh
#RUN ./configure  --enable-hardening --with-boost-libdir=/usr/lib/x86_64-linux-gnu --with-incompatible-bdb
# build everything
#RUN make clean
#RUN make install
#RUN make check
