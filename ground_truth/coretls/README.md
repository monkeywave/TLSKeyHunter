# CoreTLS

As stated in the [presentation](https://rp.os3.nl/2015-2016/p52/presentation.pdf) by Tom Curran and Marat Nigmatullin, CoreTLS is provided through the [Secure Transport API](https://developer.apple.com/documentation/security/secure-transport). This API is deprecated and supports only up to TLS 1.2.  

Furthermore, CoreTLS was originally designed exclusively for the Darwin environment. By leveraging the Darling compatibility layer, it is possible to run Darwin binaries on a Linux system. To demonstrate that our approach is functional, we provide a TLS 1.2 client for [Darling-CoreTLS](https://github.com/darlinghq/darling-coretls).
