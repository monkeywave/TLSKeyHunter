# BotanSSL

We use the Dockerfile to build the different versions of the BotanSSL client.
You should find the compiled test clients in the folder `compiled_clients`.

The version of BotanSSL can be identified in the `compiled_clients`.

## Build the Docker Image

We assume, that you are running this from this directory

Build the Docker Image:
```bash
mkdir -p compiled_clients/ && docker build -t botanssl-client .
```

## Run the Docker Image (compiling the binaries)

```bash
docker run --rm -v $(pwd)/compiled_clients:/compiled_clients botanssl-client
```

## Run the static Client Version
```bash
./compiled_clients/test_client_12_botanssl
```

## Run the dynamic Client Version
```bash
LD_LIBRARY_PATH=./compiled_clients/libs ./compiled_clients/test_client_12_botanssl_dl
```