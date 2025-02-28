# Use the official Ubuntu base image
FROM ubuntu:latest

# Install OpenSSL
RUN apt-get update && apt-get install -y openssl && apt-get clean

# Copy the SSL certificates into the container
COPY certs/server.crt /etc/ssl/certs/server.crt
COPY certs/server.key /etc/ssl/private/server.key

# Copy the entrypoint script into the container
COPY entrypoint.sh /entrypoint.sh

# Make the entrypoint script executable
RUN chmod +x /entrypoint.sh

# Expose the port that the server will listen on
EXPOSE 4433 4432

# Set the entrypoint script
ENTRYPOINT ["/entrypoint.sh"]
