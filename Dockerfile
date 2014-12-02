FROM myvbo/cloudserver-48.153
MAINTAINER Scott Spangenberg
RUN sudo apt-get update

ADD . /home/myvbo/cloudwallets/litecoin
WORKDIR /home/myvbo/cloudwallets/litecoin/src
RUN find . -type f -exec touch {} ";"
RUN make -f makefile.unix clean
RUN make -f makefile.unix STATIC=1 RELEASE=1 64BIT=1 USE_QRCODE=1 USE_UPNP=1 BDB_INCLUDE_PATH=/home/myvbo/cloudwallets/db-4.8.30/build_unix/ BDB_LIB_PATH=/usr/local/BerkeleyDB.4.8/lib BOOST_INCLUDE_PATH=/usr/local/boost1.53.0/include BOOST_LIB_PATH=/usr/local/boost1.53.0/lib
RUN make -f makefile.unix STATIC=1 RELEASE=1 64BIT=1 USE_QRCODE=1 USE_UPNP=1 BDB_INCLUDE_PATH=/home/myvbo/cloudwallets/db-4.8.30/build_unix/ BDB_LIB_PATH=/usr/local/BerkeleyDB.4.8/lib BOOST_INCLUDE_PATH=/usr/local/boost1.53.0/include BOOST_LIB_PATH=/usr/local/boost1.53.0/lib test
RUN  ./test_litecoin

ENTRYPOINT ["/home/myvbo/cloudwallets/litecoin/src/litecoind", "-datadir=/coin/litecoin"]
CMD ["-conf=/coin/litecoin/litecoin.conf"]
EXPOSE 3000
