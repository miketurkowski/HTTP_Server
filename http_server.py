import logging
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
        # Split the request by lines
        lines = request_file.split('\n')

        # Extract the first line, which contains the request method, resource, and HTTP version
        request_line = lines[0].split(' ')
        method = request_line[0]
        resource = request_line[1]
        http_version = request_line[2]

        # Check if the method is supported
        if method not in HTTP_methods:
            return not_implemented_response
        
        #Check if the HTTP version is supported
        if http_version not in ['HTTP/1.0', 'HTTP/1.1']:
            return http_version_not_supported_response

        # Return the method, resource, and HTTP version if both are supported
        return method, resource, http_version

    except Exception as e:
        logging.error(f'Error parsing the request: {e}')
        return internal_server_error_response

# Define the function to start the server
def start_server(ip, port, certificate, key):
    try:
        # Create a socket
        server_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind the socket to the given IP and port
        server_socket.bind(('0.0.0.0',8080))
        # Start listening on the socket
        server_socket.listen(5)
    except Exception as e:
        logging.error(f'Error binding the socket: {e}')
        server_socket.close()
        sys.exit(1)

    while True:
        try:
            # Accept an incoming connection
            client_socket, address = server_socket.accept()
            print(f'Accepted connection from {address}')

            # If certificate and key are provided, enable HTTPS
            if certificate and key:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(certificate, key)
                try:
                    client_socket = context.wrap_socket(client_socket, server_side=True)
                except Exception as e:
                    logging.error(f'Error setting up the SSL context: {e}')
        
            try:
                # Receive data from the client
                data = client_socket.recv(1024)

                # Decode the received data and pass it to the handle_request function
                request = data.decode('utf-8')
                method, resource, http_version = parse_request(request)
                response, response_body = handle_request(request, resource)
  

                # Send the response back to the client
                client_socket.sendall(response.encode('utf-8'))
            
                # Log the request to a file
                logging.basicConfig(filename='server.log', level=logging.INFO,
                                    format='%(asctime)s %(message)s', datefmt='%Y-%m-%d, %H:%M:%S')
                logging.info(f'{method} {resource} {http_version} -INFO')

            except Exception as e:
                logging.error(f'Error sending response: {e}')
        except Exception as e:
            logging.error(f'Error accepting connection: {e}')
            continue

        # Close the socket after send the request
        client_socket.close()

def handle_request(request_file, resource):
    # Check if the requested resource is a PHP script
    if resource.endswith('.php'):
        # Build the environment for php-cgi to execute the script
        env = os.environ.copy()
        env['REQUEST_METHOD'] = 'GET' if request_file.startswith('GET') else 'POST'
        env['QUERY_STRING'] = resource.split('?')[1] if '?' in resource else ''
        env['CONTENT_TYPE'] = 'application/x-www-form-urlencoded'
        env['CONTENT_LENGTH'] = str(len(request_file.split('\r\n')[-1]))

        # Execute the script using php-cgi
        try:
            process = subprocess.Popen(['php-cgi'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
            response_body, _ = process.communicate(input=request_file.split('\r\n')[-1].encode('utf-8'))
        except Exception as e:
            logging.error(f'Error executing the PHP script: {e}')
            response = internal_server_error_response
            response_body = str(e).encode('utf-8')
        else:
            # Format the output as the body of an HTTP response
            response = valid_response
            response += f'Content-Length: {len(response_body)}\r\n'
            response += '\r\n'
            response += response_body
    else:
        # Return a 404 Not Found response if the requested resource is not a PHP script
        response = not_found_response
        response_body = b''

    # Return a valid response for non-PHP requests
    return response, response_body

    # Log the request to a file
    logging.basicConfig(filename='server.log', level=logging.INFO,
        format='%(asctime)s %(message)s', datefmt='%Y-%m-%d, %H:%M:%S')
    logging.info(f'{method} {resource} {http_version} -INFO')

    # Return a valid response for non-PHP requests
    return valid_response, b''

# Check if the script is being run as the main program
if __name__ == '__main__':
    if len(sys.argv) != 5:
        print('Usage: http_server_dev.py <ip> <port> <certificate> <key>')
        sys.exit(1)

    # Extract the command line arguments and store them in variables
    ip = sys.argv[1]
    port = int(sys.argv[2])
    certificate = sys.argv[3]
    key = sys.argv[4]

    # Call the start_server function with the extracted arguments
    start_server(ip, port, certificate, key)