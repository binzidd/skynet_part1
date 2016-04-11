import struct
from Crypto.Cipher import AES

from dh import aes_iv
from dh import dh_key_creation, calculate_dh_secret
from dh import prime
from lib import globalvariables


class StealthConn(object):

    def __init__(self, conn, client=False, server=False, verbose=False):  # added status=false
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.initiate_session()
        # self.check_public_key()  #changes made

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = dh_key_creation()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(shared_hash))
            key = shared_hash
            iv = aes_iv()
            self.cipher = AES.new(key, AES.MODE_CBC, iv)
            # 32 byte key length AES-256

    def verify_publickey(self):  # inserting to check our keys
        check_their_public_key = int(self.recv())  # checking the value of thier public key
        if check_their_public_key in [2, prime - 1]:
            self.publickeystatus = True
        else:
            print("Key not in range : EVE EVE EVE incoming")
            self.publickeystatus = False
            # return self.publickeystatus
    def send(self, data):
        if self.publickeystatus == False:
            self.conn.close()  # if the public key doesnot fall in the prime space, then connection is closed with the above message
        else:
            if self.cipher:
                encrypted_data = self.cipher.encrypt(data)
            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
            else:
                encrypted_data = data
            # Encode the data's length into an unsigned two byte int ('H') http://www.di-mgt.com.au/cryptoCipherText.html
            globalvariables.counter_sender +=1
            pkt_len = struct.pack('H', len(encrypted_data))
            self.conn.sendall(pkt_len)
            self.conn.sendall(encrypted_data)
            self.conn.sendall(counter_value) #implementing counter :: need to check the counter value here

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        globalvariables.counter_receiver+=1 #written to implement counter
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]
        encrypted_data = self.conn.recv(pkt_len)
        counter_sender_value = self.conn.recv(globalvariables.counter_sender) #receiving the counter value
        if counter_sender_value == globalvariables.counter_receiver : #comparing the values of counter sender and counter receiver
            if self.cipher:
                data = self.cipher.decrypt(encrypted_data)
            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
            else:
                data = encrypted_data
            return data
        else :
            print("replay attack detected")
            self.conn.close


    def close(self):
        self.conn.close()