# Use the official Ubuntu 20.04 image as the base image
FROM ubuntu:20.04

# Update the package list and install Python 3 and OpenSSL
RUN apt-get update && apt-get install -y python3 openssl

# Copy the server files to the container
COPY http_server_prod.py /http_server/
COPY index.html /http_server/
COPY test.php /http_server/
COPY cert.pem /http_server/
COPY key.pem /http_server/

# Set the working directory
WORKDIR /http_server

# Expose port 8080 for the server
EXPOSE 8080

# Start the server
CMD ["python3", "http_server_prod.py", "0.0.0.0", "8080", "cert.pem", "key.pem"]

