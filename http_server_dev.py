import logging
import mimetypes
import os
import socket
import ssl
import subprocess
import sys

# Define a list of HTTP methods
HTTP_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD']

# Define response messages
valid_response = 'HTTP/1.1 200 OK\r\n'
created_response = 'HTTP/1.1 201 CREATED\r\n'
bad_request_response = 'HTTP/1.1 400 BAD REQUEST\r\n'
forbidden_response = 'HTTP/1.1 403 FORBIDDEN\r\n'
not_found_response = 'HTTP/1.1 404 NOT FOUND\r\n'
length_required_response = 'HTTP/1.1 411 LENGTH REQUIRED\r\n'
internal_server_error_response = 'HTTP/1.1 500 INTERNAL SERVER ERROR\r\n'
not_implemented_response = 'HTTP/1.1 501 NOT IMPLEMENTED\r\n'
http_version_not_supported_response = 'HTTP/1.1 505 HTTP VERSION NOT SUPPORTED\r\n'

# Define the function to parse the contents of a request
def parse_request(request_file):
    try:
        if not request_file:
            return bad_request_response

        # Split the request by lines
        lines = request_file.split('\n')

        # Extract the first line, which contains the request method, resource, and HTTP version
        request_line = lines[0].split(' ')
        method = request_line[0]
        resource = request_line[1]
        http_version = (request_line[2]).strip()

        # Check if the method is supported
        if method not in HTTP_methods:
            return not_implemented_response
        
        #Check if the HTTP version is supported
        if http_version not in ['HTTP/1.0', 'HTTP/1.1']:
            return http_version_not_supported_response

        # Return the method, resource, and HTTP version if both are supported
        return method, resource, http_version

    except Exception as e:
        logging.exception(f'Error parsing the request: {e}')
        return internal_server_error_response

# Define the function to start the server
def start_server(ip, port, certificate=None, key=None):

    # Set up the logger
    logging.basicConfig(filename='server.log', level=logging.INFO,
                        format='%(asctime)s %(message)s', datefmt='%Y-%m-%d, %H:%M:%S')
    logger = logging.getLogger(__name__)

    # Validate command line arguments
    if not all((ip, port)):
        logger.exception('Usage: http_server_dev.py <ip> <port> [<certificate> <key>]')
        sys.exit(1)
    if certificate and not key:
        logger.exception('Error: Certificate is provided but private key is missing')
        sys.exit(1)

    # Create a socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((ip, port))
        server_socket.listen(5)
        logger.info(f'Server listening on {ip}:{port}')

        while True:
            try:
                # Accept an incoming connection
                client_socket, address = server_socket.accept()
                logger.info(f'Accepted connection from {address}')

                # If certificate and key are provided, enable HTTPS
                if certificate and key:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(certificate, key)
                    try:
                        with context.wrap_socket(client_socket, server_side=True) as secure_socket:
                            handle_client_connection(secure_socket, logger)
                    except Exception as e:
                        logger.exception(f'Error setting up the SSL context: {e}')
                        client_socket.close()
                        continue
                else:
                    with client_socket:
                        handle_client_connection(client_socket, logger)

            except Exception as e:
                logger.exception(f'Error accepting connection: {e}')
                continue

def handle_client_connection(client_socket, logger):
    try:
        # Receive data from the client
        data = client_socket.recv(1024)

        # Decode the received data and pass it to the handle_request function
        request = data.decode('utf-8')
        method, resource, http_version = parse_request(request)
        response, response_body = handle_request(request, resource)

        # Send the response back to the client
        client_socket.sendall(response.encode('utf-8'))

        # Log the request
        logger.info(f'{method} {resource} {http_version} -INFO')

    except Exception as e:
        logger.exception(f'Error sending response: {e}')

def handle_php_request(request_file, resource):
    # Build the environment for php-cgi to execute the script
    env = os.environ.copy()
    env['REQUEST_METHOD'] = 'GET' if request_file.startswith('GET') else 'POST'
    env['QUERY_STRING'] = resource.split('?')[1] if '?' in resource else ''
    env['CONTENT_TYPE'] = 'application/x-www-form-urlencoded'
    env['CONTENT_LENGTH'] = str(len(request_file.split('\r\n')[-1]))
    env['REDIRECT_STATUS'] = '1' # Set REDIRECT_STATUS variable

    # Set the SCRIPT_FILENAME environment variable to the absolute path of the PHP script
    script_filename = '/test.php'
    env['SCRIPT_FILENAME'] = f'{os.getcwd()}{script_filename}' # Include full path to test.php

    # Log the SCRIPT_FILENAME environment variable
    logging.info(f'SCRIPT_FILENAME={env["SCRIPT_FILENAME"]}')

    # Execute the script using php-cgi
    try:
        process = subprocess.Popen(['/usr/bin/php-cgi'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
        response_body, _ = process.communicate(input=request_file.split('\r\n')[-1].encode('utf-8'))
    except Exception as e:
        logging.exception(f'Error executing the PHP script: {e}')
        response = internal_server_error_response
        response_body = str(e).encode('utf-8')
    else:
        # Format the output as the body of an HTTP response
        response = valid_response
        response += f'Content-Length: {len(response_body)}\r\n'
        response += '\r\n'
        response += response_body.decode('utf-8')  # Decode response_body to string

    # Return the response and response body
    return response, response_body

def handle_request(request_file, resource):
    # Check if the requested resource exists
    if not os.path.exists(resource):
        response = not_found_response
        response_body = b''

    # Check if the requested resource is readable
    elif not os.access(resource, os.R_OK):
        response = forbidden_response
        response_body = b''

    # Handle PHP requests separately
    elif resource.endswith('.php'):
        print(f'request_file: {request_file}')
        print(f'resource: {resource}')
        response, response_body = handle_php_request(request_file, resource)

    # Return a valid response for non-PHP requests
    else:
        with open(resource, 'rb') as f:
            content_type, _ = mimetypes.guess_type(resource)
            content_type = content_type or 'application/octet-stream'
            response = valid_response
            response += f'Content-Type: {content_type}\r\n'
            response += f'Content-Length: {os.path.getsize(resource)}\r\n'
            response += '\r\n'
            response_body = f.read()

    # Return the response and response body
    return response, response_body

# Check if the script is being run as the main program
if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Usage: http_server_dev.py <ip> <port> [<certificate> <key>]')
        sys.exit(1)

    # Extract the command line arguments and store them in variables
    ip = sys.argv[1]
    port = int(sys.argv[2])
    certificate = sys.argv[3] if len(sys.argv) > 3 else None
    key = sys.argv[4] if len(sys.argv) > 4 else None

    # Call the start_server function with the extracted arguments
    start_server(ip, port, certificate, key)
