
# make sl5
# (first, in luazen, make clean ; make luazen.a)

#~ LUA= ../../lua/src
LUA= ../../lua-5.3.5/src
L5= ../../l5
LZ= ../../luazen
LN= ../../slua/src

CC= /opt/musl/bin/musl-gcc
AR= ar

CFLAGS= -static -Os -I$(LUA) -I$(LZ)/src -I$(LN)
LDFLAGS= 

sl5:
	$(CC) -o liblua.o  $(CFLAGS) -DMAKE_LIB -c lone.c
	$(CC)  $(CFLAGS) -o linenoise.o -c $(LN)/linenoise.c
	$(CC)  $(CFLAGS) -o l5.o -c $(L5)/l5.c
	$(CC)  $(CFLAGS) -o sl5.o  -c sl5.c
	$(CC) -static -o sl5 sl5.o linenoise.o l5.o liblua.o $(LZ)/luazen.o  $(LZ)/luazen.a
	strip sl5

luas:
	$(CC) -o liblua.o  $(CFLAGS) -DMAKE_LIB -c lone.c
	$(CC)  $(CFLAGS) -o linenoise.o -c $(LN)/linenoise.c
	$(CC)  $(CFLAGS) -o luas.o  -c luas.c
	$(CC) -static -o luas luas.o linenoise.o liblua.o
	strip luas

clean:
	rm -f *.o sl5 luas


