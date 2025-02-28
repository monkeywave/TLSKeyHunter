# OpenSSL

We use the Dockerfile to build the different versions of the OpenSSL client.
You should find the compiled test clients in the folder `compiled_clients`.

The version of OpenSSL can be identified in the `compiled_clients`.

## Build the Docker Image

We assume, that you are running this from this directory

Build the Docker Image:
```bash
mkdir -p compiled_clients/ && docker build -t openssl-client .
```

## Run the Docker Image (compiling the binaries)

```bash
docker run --rm -v $(pwd)/compiled_clients:/compiled_clients openssl-client
```


## Running the dynamic linked version

Copy the generated libraries to your current working directory:
```bash
cp tls_library_ground_truth/openssl/compiled_clients/libs/* ./dl_libs/
``` 

Than before running the test application ensure that the linker path is set accordingly: 
```bash
export LD_LIBRARY_PATH=./dl_libs
./test_client_13_openssl_key_export_dl
``` 