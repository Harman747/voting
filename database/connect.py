import mysql.connector as cnc

def connect_to_database():

    return cnc.connect(
        host = 'localhost',
        username = 'root',
        password = 'Harman@5056',
        database = 'elixir'
        )