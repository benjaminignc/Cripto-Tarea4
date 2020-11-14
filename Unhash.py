import os
from argon2 import PasswordHasher
from timeit import default_timer as timer
import socket
import sys
import donna25519

#unhash = os.system('hashcat -m 0 -a 0 -D 2 -o archivo_1_unhashed.txt --outfile-format=2 archivo_1 diccionario_2.dict') #MD5
#unhash = os.system('hashcat -m 11 -a 0 -D 2 -o archivo_2_unhashed.txt --outfile-format=2 archivo_2 diccionario_2.dict') #Joomla < v2.5.18
#unhash = os.system('hashcat -m 11 -a 0 -D 2 -o archivo_3_unhashed.txt --outfile-format=2 archivo_3 diccionario_2.dict') #Joomla < v2.5.18
#unhash = os.system('hashcat -m 1000 -a 0 -D 2 -o archivo_4_unhashed.txt --outfile-format=2 archivo_4 diccionario_2.dict') #NTLM
#unhash = os.system('hashcat -m 1800 -a 0 -D 2 -o archivo_5_unhashed.txt --outfile-format=2 archivo_5 diccionario_2.dict') #sha512crypt $6$, SHA512 (Unix)

#Proceso de rehasheo de contraseñas
'''ph=PasswordHasher()
for n in range(5):
    start=timer()
    f = open('archivo_'+str(n+1)+'_unhashed.txt', "r")
    for linea in f:
        password_hash=ph.hash(linea)
        f_hash = open('archivo_'+str(n+1)+'_rehashed.txt',"a")
        f_hash.write(password_hash+'\n')
        f_hash.close()
    f.close()
    end=timer()
    total=end-start
    print('Tiempo de rehasheo de archivo '+str(n+1)+': '+str(total)+' segundos.')'''

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 10000)
print('starting up on {} port {}'.format(*server_address))
sock.bind(server_address)

sock.listen(1)

private_key = donna25519.PrivateKey()
public_key = private_key.get_public()
print(public_key.public)

while True:
    # Wait for a connection
    print('waiting for a connection')
    connection, client_address = sock.accept()
    try:
        print('connection from', client_address)

        # Receive the data in small chunks and retransmit it
        while True:
            data = connection.recv(32)
            print('received {!r}'.format(data))
            if data:
                print('sending public key to the client')
                connection.sendall(public_key.public)
                shared_secret=private_key.do_exchange(data)
                print(shared_secret)
            else:
                print('no data from', client_address)
                break
            

    finally:
        connection.close()
        break