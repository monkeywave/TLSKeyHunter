# Rustls

We use the Dockerfile to build the different versions of the Rustls client.
You should find the compiled test clients in the folder `compiled_clients`.

The version of Rustls can be identified in the `compiled_clients`.

## Build the Docker Image

We assume, that you are running this from this directory

Build the Docker Image:
```bash
mkdir -p compiled_clients/ && docker build -t rustls-client .
```

## Run the Docker Image (compiling the binaries)

```bash
docker run --rm -v $(pwd)/compiled_clients:/compiled_clients rustls-client
```