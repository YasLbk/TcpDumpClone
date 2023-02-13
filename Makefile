CFLAGS = -Wall -lpcap
CC = gcc
C_SOURCES = layer7_app.c layer4_tp.c layer3_netw.c layer1_eth.c main.c
BIN = analyseur
DELFILE = $(BIN)

all:
	$(CC) $(C_SOURCES) $(CFLAGS) -o $(BIN)

clean:
	rm $(DELFILE)
