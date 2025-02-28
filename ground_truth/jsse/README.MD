# JSSE

We use the Dockerfile to build the different versions of the JSSE client.
You should find the compiled test clients in the folder `compiled_clients`.

The version of JSSE can be identified in the `compiled_clients`.

## Build the Docker Image

We assume, that you are running this from this directory

Build the Docker Image:
```bash
mkdir -p compiled_clients/ && docker build -t JSSE-client .
```

## Run the Docker Image (compiling the binaries)

```bash
docker run --rm -v $(pwd)/compiled_clients:/compiled_clients JSSE-client
```

## Run the compiled client applications
```bash
cd ./compiled_clients
```

### Run the Basic Clients
```bash
java -jar test_client_12_jsse.jar
```

### Run the TLS 1.2 Export Client
```bash
java --add-opens java.base/sun.security.ssl=ALL-UNNAMED --add-opens java.base/java.lang=ALL-UNNAMED -jar test_client_12_jsse_key_export.jar
```

### Run the TLS 1.3 Export Client
```bash
./test_client_13_jsse_key_export.sh
```