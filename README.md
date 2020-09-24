# example-secure-bootrom
A basic example of Secure Boot ROM for embedded platform.



## Tests
To compile test from freedom-e-sdk use:

```
make PROGRAM=example-secure-bootrom TARGET=<your target> CONFIGURATION=debug TEST=TRUE VERBOSE=TRUE software
```

Note that `TEST=TRUE` enable the test
 