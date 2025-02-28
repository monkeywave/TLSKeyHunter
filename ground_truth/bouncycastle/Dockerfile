# Use the official Ubuntu base image
FROM ubuntu:latest

# Set environment variables to avoid interactive prompts during the build
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Berlin

# Install dependencies
RUN apt-get update && apt-get install -y \
    openjdk-21-jdk \
    maven \
    && apt-get clean

# Set Version
ENV PINNED_VERSION_JAVA="openjdk 21"
ENV PINNED_VERSION="bouncycastle 1.79"

# Set the working directory
WORKDIR /bouncycastle

# Copy the source code into the container
COPY /src/ /bouncycastle/src/
COPY /pom.xml /bouncycastle/

RUN echo '#!/bin/bash\n' > /start.sh && \
    echo 'mvn clean package' >> /start.sh && \
    echo 'mv /bouncycastle/target/test_client_12_bouncycastle-jar-with-dependencies.jar /bouncycastle/target/test_client_12_bouncycastle.jar' >> /start.sh && \
    echo 'mv /bouncycastle/target/test_client_13_bouncycastle-jar-with-dependencies.jar /bouncycastle/target/test_client_13_bouncycastle.jar' >> /start.sh && \
    echo 'mv /bouncycastle/target/test_client_12_bouncycastle_key_export-jar-with-dependencies.jar /bouncycastle/target/test_client_12_bouncycastle_key_export.jar' >> /start.sh && \
    echo 'mv /bouncycastle/target/test_client_13_bouncycastle_key_export-jar-with-dependencies.jar /bouncycastle/target/test_client_13_bouncycastle_key_export.jar' >> /start.sh && \
    echo 'cp /bouncycastle/target/test_client_12_bouncycastle.jar /bouncycastle/target/test_client_13_bouncycastle.jar /bouncycastle/target/test_client_12_bouncycastle_key_export.jar /bouncycastle/target/test_client_13_bouncycastle_key_export.jar /compiled_clients/' >> /start.sh && \
    echo 'echo Java: $PINNED_VERSION_JAVA > /compiled_clients/version.md' >> /start.sh && \
    echo 'echo TLS Library: ${PINNED_VERSION} >> /compiled_clients/version.md' >> /start.sh && \
    chmod +x /start.sh

CMD ["/start.sh"]