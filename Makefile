OBJS = json-parser.o ../libthttp/jsmn/jsmn.o ../libthttp/jsmn/jsmnutil.o utils.o


CFLAGS += -Wunused -g -I ../libthttp/ -I ./

all:	clean json-parser

json-parser:	$(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^

%.o:	$(PROJECT_ROOT)%.cpp
	$(CXX) -c $(CFLAGS) $(CXXFLAGS) $(CPPFLAGS) -o $@ $<

%.o:	$(PROJECT_ROOT)%.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) -o $@ $<

clean:
	rm -fr json-parser $(OBJS)
