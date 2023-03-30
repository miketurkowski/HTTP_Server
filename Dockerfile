FROM ubuntu:20.04

# set environment variable to avoid prompts
ENV DEBIAN_FRONTEND noninteractive

# update package lists
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y python3 python3-pip openssl php-cgi

# install required python packages
RUN pip3 install requests pyopenssl

# copy over files
COPY http_server_dev.py /http_server_dev.py
COPY cert.pem /cert.pem
COPY key.pem /key.pem
COPY test.php /test.php

# add executable permissions to test.php
RUN chmod +x /test.php

# expose port 8080
EXPOSE 8080

# start the server
CMD ["python3", "/http_server_dev.py", "0.0.0.0", "8080", "/cert.pem", "/key.pem"]


