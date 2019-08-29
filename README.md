# KTLS-Demo

This is a server demo using Kernel TLS encryption. The details of using KTLS are encapsulated in openssl, so using `SSL_sendfile` directly can reduce a lot of mental burden. If you want to learn more about how to enable kernel tls, you can check this repo: [OpenSSL with SSL_sendfile](https://github.com/hunterlxt/openssl)

KTLS feature must be enabled.

```shell
sudo modprobe tls
lsmod | grep tls
```

## Build

Before building, you need to clone this repository and download submodules containing source code for Demo's dependencies.

Then specify the shared library path.

To build the code, just `make`. It will generate private key and certificates file in the directory.

```shell
git submodule update --init
cd ./openssl
./config && make -j6
cd ..
export LD_LIBRARY_PATH=./openssl
make
```
