CC := ../toolchains/mips-linux-musl/bin/mips-linux-musl-gcc

TARGETS = init

CFLAGS := -g -fPIC -static -I../external/lxc/src/ 
PREREQS := ../out/malta/build/lxc/obj/src/lxc/liblxc.a

all: $(TARGETS)

OBJ := init.c loop.c tsh.c config.c

init: 
	$(CC) $(CFLAGS) $(OBJ) -o $@ $(PREREQS)

clean:
	rm -f $(TARGETS)
