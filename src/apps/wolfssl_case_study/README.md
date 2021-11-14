# WolfSSL ECDSA Case Study

A bitcode file with the [WolfSSL](https://github.com/wolfSSL/wolfssl) code is already provided in the repo. 
To extract the bitcode we build WolfSSL using [gllvm](https://github.com/SRI-CSL/gllvm), so install it first.
If you want to build it yourself:
```bash
./download_wolfssl.sh
./extract_bc.sh
```

To linearize the ECC modular multiplication invoked in the `test.c` source:
```bash
./run.sh
```

This will produce a hardened `test.out` binary, and an unhardened version `test.orig.out`