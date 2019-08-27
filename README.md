# KTLS-Demo

This is a server demo using Kernel TLS encryption.

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
./config enable-ktls && make -j6 && make test
cd ..
export LD_LIBRARY_PATH=./openssl
make
```
