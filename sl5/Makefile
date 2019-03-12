
# make sl5

LUA= ../../lua/src
L5= ../../l5
LZ= ../../luazen/src
LN= ../../slua/src/linenoise

CC= /opt/musl/bin/musl-gcc
AR= ar

CFLAGS= -static -Os -I$(LUA) -I$(LZ) -I$(LN)
LDFLAGS= 

sl5:
	$(CC) -o liblua.o  $(CFLAGS) -DMAKE_LIB -c lone.c
	$(CC)  $(CFLAGS) -o linenoise.o -c $(LN)/linenoise.c
	$(CC)  $(CFLAGS) -o l5.o -c $(L5)/l5.c
	$(CC)  $(CFLAGS) -o lz.o -c lz.c
	$(CC)  $(CFLAGS) -o sl5.o  -c sl5.c
	$(CC) -static -o sl5 sl5.o linenoise.o l5.o lz.o liblua.o
	strip sl5

clean:
	rm *.o sl5


