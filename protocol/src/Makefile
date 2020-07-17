CC = gcc
CFLAGS = -Wall -I../include
DEPS = ../include

OBJ = main.o handle_connect.o send_connack.o mosquitto_property.o mosquitto_base.o 

	
%.o:%.c $(DEPS) 
	$(CC) -c -o $@ $< $(CFLAGS)

nanomqlib:$(OBJ) 
	$(CC) -o $@ $< 

.PHONY:clean
clean:
	rm -f *.o nanomqlib
