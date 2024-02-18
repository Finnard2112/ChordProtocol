CC=gcc
CFLAG_INCLUDE=-I. -Iinclude -Iprotobuf
CFLAGS=-Wall $(CFLAG_INCLUDE) -Wextra -std=gnu99 -ggdb
LDLIBS=-lprotobuf-c -lcrypto
SRC=src
VPATH= $(SRC) include protobuf

all: chord_protobuf chord

chord_protobuf:
	protoc-c --c_out=. protobuf/chord.proto

chord: ./src/hash.c ./src/chord_arg_parser.c ./protobuf/chord.pb-c.c ./src/chord.c ./src/utils.c
	$(CC) $(CFLAGS) -o chord ./src/hash.c ./src/chord_arg_parser.c ./protobuf/chord.pb-c.c ./src/chord.c ./src/utils.c $(LDLIBS)

clean:
	rm -rf protobuf/*.pb-c.* *~ chord *.o

.PHONY : clean all
