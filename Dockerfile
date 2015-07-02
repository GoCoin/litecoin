FROM myvbo/cloudserver-48.154:latest
MAINTAINER Scott Spangenberg

# To build the docker container:
# git clone git@github.com:Ziftr/litecoin.git litecoin
# git branch NewRPC
# cp litecoin.dock litecoin/Dockerfile && time docker build --rm=true -t myvbo/litecoin-qt-server:latest litecoin
# To run the Docker container:
# docker run --rm -t -i --entrypoint="/bin/bash" myvbo/litecoin-qt-server
# To propagate the binaries for building a minimized server from directory litecoin_server
# docker run --rm -t -i --entrypoint="/bin/bash" -v ~/myvbo/qtwalletbase/litecoin_server:/home/myvbo/cloudwallets/serverbinaries myvbo/litecoin-qt-server
# cp litecoind test_litecoin /home/myvbo/cloudwallets/serverbinaries
# cp -r data /home/myvbo/cloudwallets/serverbinaries/data

# Install these GNU utilities to get scanelf so we can confirm hardening of the executable
RUN apt-get -y install pax-utils

ADD . /home/myvbo/cloudwallets/litecoin
WORKDIR /home/myvbo/cloudwallets/litecoin
RUN mv git ../.git
WORKDIR /home/myvbo/cloudwallets/litecoin/src
RUN find . -type f -exec touch {} ";"
RUN make -f makefile.unix clean
RUN make -f makefile.unix STATIC=1 RELEASE=1 64BIT=1 USE_QRCODE=1 USE_UPNP=1 BDB_INCLUDE_PATH=/home/myvbo/cloudwallets/db-4.8.30/build_unix/ BDB_LIB_PATH=/usr/local/BerkeleyDB.4.8/lib
RUN make -f makefile.unix STATIC=1 RELEASE=1 64BIT=1 USE_QRCODE=1 USE_UPNP=1 BDB_INCLUDE_PATH=/home/myvbo/cloudwallets/db-4.8.30/build_unix/ BDB_LIB_PATH=/usr/local/BerkeleyDB.4.8/lib test

# Cleanup
WORKDIR /home/myvbo/cloudwallets/litecoin
RUN cp src/litecoind litecoind
RUN cp src/test_litecoin test_litecoin
RUN cp -r src/test/data data
# Enable the next line to remove debug info from the copied executables
RUN strip litecoind
RUN strip test_litecoin

# Test
RUN  /home/myvbo/cloudwallets/litecoin/test_litecoin
# Don't test litecoin-qt if we aren't building litecoin-qt
#RUN /home/myvbo/cloudwallets/litecoin/src/qt/test/test_litecoin-qt

ENTRYPOINT ["/home/myvbo/cloudwallets/litecoin/litecoind", "-datadir=/coin/litecoin"]
CMD ["-conf=/coin/litecoin/litecoin.conf"]
EXPOSE 3000
