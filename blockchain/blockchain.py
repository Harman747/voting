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
import mysql.connector

my_database = connect_to_database()
my_cursor = my_database.cursor()
    

class blockchain() :

    def __init__(self):
        self.my_blockchain = []
        self.dif = 4 # Adjustable difficulty level
        self.load_rsa_keys()  # Load RSA keys
        self.prev_hash = self.gen_first_block()  # Generate first block

    def load_rsa_keys(self):
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
                    self.pvt_key = RSA.import_key(f.read())
                with open(public_key_path, "rb") as f:
                    self.pub_key = RSA.import_key(f.read())
            except ValueError as e:
                print(f"Error loading RSA keys: {e}")
        else:
            # Generate new RSA keys and store them
            self.pvt_key = RSA.generate(2048)
            self.pub_key = self.pvt_key.public_key()

            try:
                with open(private_key_path, "wb") as f:
                    f.write(self.pvt_key.export_key(format='PEM'))
                with open(public_key_path, "wb") as f:
                    f.write(self.pub_key.export_key(format='PEM'))
            except Exception as e:
                print(f"Error saving RSA keys: {e}")
        # RSA encryption settings for encrypting AES key
        self.enc_settings = PKCS1_OAEP.new(self.pub_key, hashAlgo=SHA256)
        self.dec_settings = PKCS1_OAEP.new(self.pvt_key, hashAlgo=SHA256)

    def enc_data(self , data):
        return self.enc_settings.encrypt(str(data).encode()) #encrypt using sha 256 after converting to byte

    def load_chain_from_db(self):
        conn = mysql.connector.connect(user="root", password="Harman@5056", host="localhost", database="elixir")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM block ORDER BY id ASC")
        rows = cursor.fetchall()
        self.my_blockchain = rows
        conn.close()

    def gen_first_block(self):

        encptd_data = self.enc_data("BlockChain has started")
        party = "NULL"
        timestp = datetime.now()
        nonce = "NULL"

        curr_hash = self.cal_hash(encptd_data , nonce , party , timestp , 0)

        block = (str(0) , str(party) , str(timestp) , str(encptd_data) , str(nonce) , str(curr_hash))

        self.my_blockchain.append(block)

        self.prev_hash = curr_hash
        return curr_hash
        
    def cal_hash(self , enc_data , nonce , party , timestp , prev_hash):

        hash_str = str(prev_hash) + str(party) + str(timestp) + str(enc_data) + str(nonce)

        hash_str = hash_str.encode()

        sha_256_hash = hashlib.sha256()
        sha_256_hash.update(hash_str)

        return sha_256_hash.hexdigest()

    def print_list(self):
        print("\n\nPrinting Data\n\n\n")
        for i in self.my_blockchain:
            cnt = 0
            for j in i:

                if(cnt == 0):
                    print(f"Previous hash is: {j}")

                if(cnt==1):
                    print(f"party is: {j}")

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

    def get_nonce(self , prev_hash , enc_data ):

        nonce = 0
        while(True):

            tot_str = str(nonce) + str(enc_data) + str(prev_hash)
            
            sha256_hash = hashlib.sha256()
            sha256_hash.update(tot_str.encode())

            ans = sha256_hash.hexdigest()

            if ans.startswith(self.dif * '0'):
                print(ans)
                return nonce
            nonce += 1

    def add_to_blockchain(self , data , party):

        if(self.my_blockchain == []):
            self.prev_hash = self.gen_first_block()

        self.store_data(self.prev_hash , self.enc_data(data) , party)
        
        
    def store_data(self , prev_hash , enc_data  , party):

        timestp = str(datetime.now())
        nonce = self.get_nonce(self.prev_hash , enc_data)
        curr_hsh = self.cal_hash(enc_data , nonce , party , timestp , self.prev_hash)
        block = (str(prev_hash) , str(party) , str(timestp) , enc_data , str(nonce) , str(curr_hsh))

        self.my_blockchain.append(block)
        self.prev_hash = curr_hsh
        self.insert_in_db(prev_hash , party , timestp , enc_data , nonce)

            
    def insert_in_db(self,prev_hash , party , timestp , enc_data , nonce):
        enc_data = str(enc_data)
        query = "INSERT INTO block (prev_hash, party, timestp, enc_data, nonce ) VALUES (%s, %s, %s, %s, %s)"
        values = [
        (prev_hash, party, timestp, enc_data, nonce)
        ]

        my_cursor.executemany(query, values)
        my_database.commit()

        print("Data inserted successfully!")


new_obj = blockchain()