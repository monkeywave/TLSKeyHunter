# Bouncycastle

We use the Dockerfile to build the different versions of the Bouncycastle client.
You should find the compiled test clients in the folder `compiled_clients`.

The version of Bouncycastle can be identified in the `compiled_clients`.

## Build the Docker Image

We assume, that you are running this from this directory

Build the Docker Image:
```bash
mkdir -p compiled_clients/ && docker build -t Bouncycastle-client .
```

## Run the Docker Image (compiling the binaries)

```bash
docker run --rm -v $(pwd)/compiled_clients:/compiled_clients Bouncycastle-client
```

## Run the compiled client applications
```bash
cd ./compiled_clients
```

```bash
java -jar test_client_12_bouncycastle.jar
```
(replace test_client_12_bouncycastle.jar with the version you would like to execute)
