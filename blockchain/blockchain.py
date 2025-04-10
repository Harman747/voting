from Crypto.Cipher import AES
import mysql.connector as cnc
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from datetime import datetime
import hashlib
import os
from database.connect import connect_to_database

my_database = connect_to_database()
my_cursor = my_database.cursor()
    

class blockchain() :

    def __init__(self):
        self.__my_blockchain = []
        self.__dif = 4 # Adjustable difficulty level
        self.__load_rsa_keys()  # Load RSA keys
        self.__prev_hash = self.__gen_first_block()  # Generate first block

    def __load_rsa_keys(self):
        # Use raw string literals to avoid issues with backslashes in file paths
        private_key_path = r"C:\COLLEGE\python\python-project\keys\private.pem"
        public_key_path = r"C:\COLLEGE\python\python-project\keys\public.pem"
        # Check if directory exists, if not, create it
        directory = os.path.dirname(private_key_path)
        if not os.path.exists(directory):
            os.makedirs(directory)  # Create the directory if it doesn't exist

        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            try:
                with open(private_key_path, "rb") as f:
                    self.__pvt_key = RSA.import_key(f.read())
                with open(public_key_path, "rb") as f:
                    self.__pub_key = RSA.import_key(f.read())
            except ValueError as e:
                print(f"Error loading RSA keys: {e}")
        else:
            # Generate new RSA keys and store them
            self.__pvt_key = RSA.generate(2048)
            self.__pub_key = self.__pvt_key.public_key()

            try:
                with open(private_key_path, "wb") as f:
                    f.write(self.__pvt_key.export_key(format='PEM'))
                with open(public_key_path, "wb") as f:
                    f.write(self.__pub_key.export_key(format='PEM'))
            except Exception as e:
                print(f"Error saving RSA keys: {e}")
        # RSA encryption settings for encrypting AES key
        self.__enc_settings = PKCS1_OAEP.new(self.__pub_key, hashAlgo=SHA256)
        self.__dec_settings = PKCS1_OAEP.new(self.__pvt_key, hashAlgo=SHA256)

    def __enc_data(self , data):
        return self.__enc_settings.encrypt(str(data).encode()) #encrypt using sha 256 after converting to byte

    def __gen_first_block(self):

        encptd_data = self.__enc_data("BlockChain has started")
        index = len(self.__my_blockchain)
        timestp = datetime.now()
        nonce = "NULL"

        curr_hash = self.__cal_hash(encptd_data , nonce , index , timestp , 0)

        block = (str(0) , str(index) , str(timestp) , str(encptd_data) , str(nonce) , str(curr_hash))

        self.__my_blockchain.append(block)

        self.__prev_hash = curr_hash
        return curr_hash
        
    def __cal_hash(self , enc_data , nonce , index , timestp , prev_hash):

        hash_str = str(prev_hash) + str(index) + str(timestp) + str(enc_data) + str(nonce)

        hash_str = hash_str.encode()

        sha_256_hash = hashlib.sha256()
        sha_256_hash.update(hash_str)

        return sha_256_hash.hexdigest()

    def print_list(self):
        print("\n\nPrinting Data\n\n\n")
        for i in self.__my_blockchain:
            cnt = 0
            for j in i:

                if(cnt == 0):
                    print(f"Previous hash is: {j}")

                if(cnt==1):
                    print(f"Index is: {j}")

                if(cnt == 2):
                    print(f"TimeStamp is: {j}")

                if(cnt == 3):
                    print(f"Encrypted Data is: {j}")

                if(cnt == 4):
                    print(f"Nonce is: {j}")

                if(cnt == 5):
                    print(f"Current Hash is: {j}")

                cnt += 1

            print("\n\n")

    def __get_nonce(self , prev_hash , enc_data ):

        nonce = 0
        while(True):

            tot_str = str(nonce) + str(enc_data) + str(prev_hash)
            
            sha256_hash = hashlib.sha256()
            sha256_hash.update(tot_str.encode())

            ans = sha256_hash.hexdigest()

            if ans.startswith(self.__dif * '0'):
                print(ans)
                return nonce
            nonce += 1

    def add_to_blockChain(self):

        if(self.__my_blockchain == []):
            self.__prev_hash = self.__gen_first_block()

        data = input("Enter data\n")
        self.__store_data(self.__prev_hash , self.__enc_data(data))
        
        
    def __store_data(self , prev_hash , enc_data ):

        __index = len(self.__my_blockchain)
        print("\n",__index,"\n")
        __timestp = str(datetime.now())
        __nonce = self.__get_nonce(self.__prev_hash , enc_data)
        __curr_hsh = self.__cal_hash(enc_data , __nonce , __index , __timestp , self.__prev_hash)
        __block = (str(prev_hash) , str(__index) , str(__timestp) , enc_data , str(__nonce) , str(__curr_hsh))

        self.__my_blockchain.append(__block)
        self.__prev_hash = __curr_hsh
        self.__insert_in_db(prev_hash , __index , __timestp , enc_data , __nonce)

    def dec_data(self):

        while True:
            try:
                index = int(input("Enter Index: "))

                if index >= len(self.__my_blockchain) or index < 0:
                    print("Invalid Index! Please enter a number between 0 and", len(self.__my_blockchain) - 1)

                else:
                    break 
            except ValueError:
                print(f"Invalid input! Please enter a valid integer between {0} and {len(self.__my_blockchain)-1}")
        
        with open("C:\COLLEGE\python\python-project\pass.txt" , "r") as p:
            self.__pass = p.read()

        while True:
            
            password = input("Enter Password: ")
            if(str(password) != str(self.__pass)):
                print("Invalid Password, Try Again: ")
        
            else:
                print("Decrypting Data....")
                __block = self.__my_blockchain[index]
                __enc_data = __block[3]
                __enc_data = self.__dec_settings.decrypt(__enc_data).decode()
                print(f"\n\nDecrypted Data is:\n{__enc_data}")
                break
            
    def __insert_in_db(self,prev_hash , ind , timestp , enc_data , nonce):
        enc_data = str(enc_data)
        query = "INSERT INTO block (prev_hash, ind, timestp, enc_data, nonce ) VALUES (%s, %s, %s, %s, %s)"
        values = [
        (prev_hash, ind, timestp, enc_data, nonce)
        ]

        my_cursor.executemany(query, values)
        my_database.commit()

        print("Data inserted successfully!")


new_obj = blockchain()
while True:
    choice = int(input("Enter choice"))
    if(choice == 1):
        new_obj.add_to_blockChain()
    else:
        break