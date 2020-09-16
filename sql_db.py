import sqlite3
from sqlite3 import Error


def create_connection(path):
    connection = None

    try:
        connection = sqlite3.connect(path)
    except Error as e:
        raise Exception(f"{e} -- Error")

    return connection


def execute_query(connection, query, values=None):
    cursor = connection.cursor()

    try:
        if values:
            cursor.execute(query, (values,))
        else:
            cursor.execute(query)
    except Error as e:
        raise Exception(f"{e} -- Error")


def execute_read_query(connection, query):
    cursor = connection.cursor()
    result = None
    try:
        cursor.execute(query)
        result = cursor.fetchall()
        return result
    except Error as e:
        raise Exception(f"{e} -- Error")
