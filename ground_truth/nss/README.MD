# NSS

We use the Dockerfile to build the different versions of the NSS client.
You should find the compiled test clients in the folder `compiled_clients`.

The version of NSS can be identified in the `compiled_clients`.

## Build the Docker Image

We assume, that you are running this from this directory

Build the Docker Image:
```bash
mkdir -p compiled_clients/ && docker build -t NSS-client .
```

## Run the Docker Image (compiling the binaries)

```bash
docker run --rm -v $(pwd)/compiled_clients:/compiled_clients NSS-client
```

## Run the static Client Version
```bash
./compiled_clients/test_client_12_nss
```

## Run the dynamic Client Version
```bash
LD_LIBRARY_PATH=./compiled_clients/libs ./compiled_clients/test_client_12_nss_dl
```
Please note that when executing the dynamically linked clients with key export on a Debian system, the key log will not work. For more Information please consider issue [#4](https://gitlab.fkie.fraunhofer.de/daniel.baier/tls_library_ground_truth/-/issues/4)!