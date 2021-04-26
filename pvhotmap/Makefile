CC = gcc

OBJS = udevmap.o pvhotmap_parser.o ../../libthttp/jsmn/jsmn.o ../../libthttp/jsmn/jsmnutil.o ../utils.o

CFLAGS += -Wunused -g -I ../../libthttp/ -I ./ -I ../

LDFLAGS = -lpthread

all:	clean udevmap

udevmap: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: $(PROJECT_ROOT)%.cpp
	$(CC) -c $(CFLAGS) -o $@ $<

%.o: $(PROJECT_ROOT)%.c
	$(CC) -c $(CFLAGS) -o $@ $<

clean:
	rm -fr udevmap $(OBJS)
