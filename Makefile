all: server client

server:
	g++ server.cc -o server -lssl -lcrypto

client:
	g++ client.cc -o client -lssl -lcrypto
clean: 
	rm -f server client