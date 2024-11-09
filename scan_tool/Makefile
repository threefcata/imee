.DEFAULT_GOAL=debug

CC=gcc

SRC=src
INC=include
CFLAGS=-I$(INC) -fpic -pie -ldl
BIN=imee

_OBJ=imee.o main.o
OBJ=$(patsubst %,$(SRC)/%,$(_OBJ))

LIB=vmi.so
LIBSRC=lib

.PHONE: lib
lib: $(LIB) ;

$(LIB): $(LIBSRC)/hyp.c
	$(CC) $(CFLAGS) -O1 -nostdlib -shared $^ -o $(LIB)
# python script/get_off.py

$(SRC)/%.o : %.c 
	$(CC) -c -o $@ $(CFLAGS)

all: $(LIB) $(OBJ) 
	$(CC) -o $(BIN) $(OBJ) $(CFLAGS)

debug: CFLAGS += -DDEBUG -g
debug: all

.PHONY: clean
clean: 
	rm -f src/*.o
	rm -f $(BIN)
	rm -f $(LIB)
