# TLS_Library_Ground_Truth

Here we provide a ground truth implementation for the Linux operating system. So we created a TLS client for each of the library provided in the following list. The table is original taken from [here](https://dfrws.org/wp-content/uploads/2024/07/TLS-key-material-identification-and-extractio_2024_Forensic-Science-Internat.pdf).

| Library Name | Implemented | Repository Path | Android Implemented |
|--------------|-------------|-----------------|---------------------|
| [Botan SSL](https://botan.randombit.net/) | [x] | [./botan_ssl/](./botan_ssl/) | [*] |
| [BoringSSL](https://boringssl.googlesource.com/boringssl) | [x] | [./boringssl/](./boringssl/) | [x] |
| [Bouncy Castle](https://www.bouncycastle.org/) | [x] | [./bouncycastle/](./bouncycastle/) | [x] |
| [Secure Transport (CoreTLS)](https://developer.apple.com/documentation/security/secure_transport/) | [NA] | [./coretls/](./coretls/) | [NA] |
| [GnuTLS](https://www.gnutls.org/) | [x] | [./gnutls/](./gnutls/) | [NA] |
| [Golang crypto/tls](https://pkg.go.dev/crypto/tls) | [x] | [./gotls/](./gotls/) | [NA] |
| [Java Secure Socket Extension (JSSE)](https://docs.oracle.com/en/java/javase/17/security/java-secure-socket-extension-jsse-reference-guide.html#GUID-93DEEE16-0B70-40E5-BBE7-55C3FD432345) | [x] | [./jsse/](./jsse/) | [*] |
| [LibreSSL](https://www.libressl.org/) | [x] | [./libressl/](./libressl/) | [x] |
| [MatrixSSL (now Rambus TLS Toolkit)](https://www.rambus.com/security/software-protocols/tls-toolkit/matrix) [MatrixSSL 4-2-1](http://web.archive.org/web/20240000000000*/https://github.com/matrixssl/matrixssl/archive/4-2-1-open.tar.gz) | [x] | [./matrixssl/](./matrixssl/) | [x] |
| [Mbed TLS](https://github.com/Mbed-TLS/mbedtls) | [x] | [./mbedtls/](./mbedtls/) | [x] |
| [Network Security Services (NSS)](https://hg.mozilla.org/projects/nss) | [x] | [./nss/](./nss/) | [NA] |
| [OpenSSL](https://www.openssl.org/) | [x] | [./openssl/](./openssl/) | [x] |
| [Rustls](https://github.com/rustls/rustls) | [x] | [./rustls/](./rustls/) | [NA] |
| [s2n-TLS](https://github.com/aws/s2n-tls) | [x] | [./s2n_tls/](./s2n_tls/) | [x] |
| [Schannel SSP](https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-) | [NA] | [./schannel_ssp/](./schannel_ssp/) | [NA] |
| [wolfSSL](https://www.wolfssl.com/) | [x] | [./wolfssl/](./wolfssl/) | [x] |


\* := no export available \
NA := not available

## Running a TLS Library Implementation

This guide provides detailed instructions for running each TLS library implementation with support for both TLS 1.2 and TLS 1.3 connections. The compiled clients for each TLS implementation are located in the `<library_name>/compiled_clients` directory.

Each TLS library implementation offers two types of clients:

    - One client using TLS 1.2.
    - Another client using TLS 1.3.

Additionally, each client is available in two variants:

    - A version that prints the TLS key material.
    - A version that runs without printing key material.

For each library, a markdown file named `version.md` is included. This file contains the name of the TLS library and its corresponding version. If the library does not have a version string available, the Git commit hash and the date of the commit are used. This is achieved using the following command:

```bash
git log -1 --format="%H %cd"
```

This ensures accurate version tracking for each TLS library in the project.


## Running the TLS Server in a Docker Container

The following steps outline how to build and run an OpenSSL server within a Docker container. This method allows you to easily switch between TLS 1.2 and TLS 1.3 configurations by passing a parameter when starting the container.


### Building the Docker Container

Assuming you have the necessary files and Docker is installed, you can build the Docker image directly from the repository:
```bash
docker build -t openssl-server .
```

This command will create a Docker image named openssl-server based on the Dockerfile present in your repository.


### Running the OpenSSL Server Using Docker 

Once the Docker image is built, you can run the OpenSSL server in a container. The server can be configured to support either TLS 1.2 or TLS 1.3 by specifying the desired version as a parameter.

**Starting the Server with TLS 1.2 Support**

To start the OpenSSL server with TLS 1.2 support only, use the following command:
```bash
docker run -d -p 4432:4432 openssl-server tls1_2
```

**Starting the Server with TLS 1.3 Support**

To start the OpenSSL server with TLS 1.3 support only, use this command:
```bash
docker run -d -p 4433:4433 openssl-server tls1_3
```

**Starting the Server with TLS 1.2 and TLS 1.3 Support**

To start the OpenSSL server with both TLS 1.2 and TLS 1.3 support, use this command:
```bash
docker run -d -p 4432:4432 -p 4433:4433 openssl-server
```


## Running the TLS Server

The following examples demonstrate how to start a TLS server with OpenSSL, configured to support only TLS 1.2 or TLS 1.3.

### Running the TLS Server with TLS 1.2 Support

To start a TLS server that only supports TLS 1.2, use the following command:

```bash
openssl s_server -tls1_2 -cert server.crt -key server.key -accept 4432
```

### Running the TLS Server with TLS 1.3 Support

To start a TLS server that only supports TLS 1.3, use this command:

```bash
openssl s_server -tls1_3 -cert server.crt -key server.key -accept 4433
```

## Android Implementation
This project provides an Android implementation for most clients.

The implementations can be found either in the [APKs](./APKs/)  directory or within the individual library directories (e.g., [boringssl](./boringssl/) for BoringSSL).

Each APK includes all four versions of the client for a specific library. For more details about the Android implementation, such as the supported architectures for each application, please refer to the [Android](./Android/) directory.
