FROM ubuntu:20.04

# Update package lists
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y python3 python3-pip openssl 

# Install required python packages
RUN pip3 install requests pyopenssl

# Copy over files
COPY http_server_dev.py /http_server_dev.py
COPY cert.pem /cert.pem
COPY key.pem /key.pem
COPY test.php /test.php

# Expose port 8080
EXPOSE 8080

# Start the server
CMD ["python3", "/http_server_dev.py", "0.0.0.0", "8080", "/cert.pem", "/key.pem"]

