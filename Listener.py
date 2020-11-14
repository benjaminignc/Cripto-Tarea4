import socket, sys
import donna25519
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 10000)
print('connecting to {} port {}'.format(*server_address))
sock.connect(server_address)

private_key = donna25519.PrivateKey()
public_key = private_key.get_public()

try:

    # Send data
    message = public_key.public
    print('sending {!r}'.format(message))
    sock.sendall(message)

    # Look for the response
    amount_received = 0
    amount_expected = len(message)

    while amount_received < amount_expected:
        data = sock.recv(32)
        amount_received += len(data)
        print('received {!r}'.format(data))
        shared_secret=private_key.do_exchange(data)

finally:
    print('closing socket')
    sock.close()