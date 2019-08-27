all: server client

server:
	gcc server.c -o server -I./openssl/include -L./openssl -lssl -lcrypto

client:
	gcc client.c -o client -I./openssl/include -L./openssl -lssl -lcrypto
clean: 
	rm -f server client