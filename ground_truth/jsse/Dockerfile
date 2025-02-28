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

# Create a directory for the project
RUN mkdir /jsse/
WORKDIR /jsse/

# Copy the source files into the container
COPY version_jsse.java /jsse/
COPY /src/ /jsse/src/
COPY /pom.xml /jsse/

#Create a startup script to compile
RUN echo '#!/bin/bash\n' > /start.sh && \
    echo 'javac version_jsse.java' >> /start.sh && \
    echo 'java version_jsse' >> /start.sh && \
    echo 'mvn clean install' >> /start.sh && \
    echo 'mv /jsse/target/test_client_12_jsse-jar-with-dependencies.jar /jsse/test_client_12_jsse.jar' >> /start.sh && \
    echo 'mv /jsse/target/test_client_13_jsse-jar-with-dependencies.jar /jsse/test_client_13_jsse.jar' >> /start.sh && \
    echo 'mv /jsse/target/test_client_12_jsse_key_export-jar-with-dependencies.jar /jsse/test_client_12_jsse_key_export.jar' >> /start.sh && \
    echo 'cp /jsse/test_client_12_jsse.jar /jsse/test_client_13_jsse.jar /jsse/test_client_12_jsse_key_export.jar version.md /compiled_clients' >> /start.sh && \
    chmod +x /start.sh

# Set CMD to execute the /start.sh script with arguments (defaults to using the pinned version)
CMD ["/start.sh"]
