all: server client

server: server.o
	gcc -o server server.o -L./openssl -lssl -lcrypto 

client: client.o
	gcc -o client client.o -L./openssl -lssl -lcrypto 

server.o: server.c
	gcc -c server.c -I./openssl/include

client.o: client.c
	gcc -c client.c -I./openssl/include
clean: 
	rm -f server client *.o