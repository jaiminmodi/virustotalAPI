import mysql.connector
from mysql.connector import Error
from configparser import NoSectionError, ConfigParser


class mysqldb:

    def read_config(self):
        config = ConfigParser(allow_no_value=True)
        try:
            config.read("configfile.cfg")
        except IOError:
            print("Error: In current folder there is no configfile.cfg file. Please check the name of file.")

        try:
            username = config.get('CREDENTIALS', 'username')
            password = config.get('CREDENTIALS', 'password')
            return username, password

        except NoSectionError:
            print("Error: Unable to read the required value from config file.")
            return -1

    def initialise_dbconn(self):
        try:
            username, password = self.read_config()

            connection_config_dict = {
                'user': username,
                'password': password,
                'host': '127.0.0.1',
                'raise_on_warnings': True,
                'use_pure': False,
                'autocommit': True,
                'pool_size': 5
            }

            connection = mysql.connector.connect(**connection_config_dict)

            if connection.is_connected():
                db_Info = connection.get_server_info()
                print("Connected to MySQL Server version ", db_Info)
                cursor = connection.cursor()

                return connection, cursor

                # self.create_DbTable(cursor)

        except Error as e:
            print("Error while connecting to MySQL", e)

    def checkTableExists(self, dbcursor, tablename):
        dbcursor.execute("""SELECT COUNT(*) FROM information_schema.tables WHERE table_name = '{0}' """.format(
            tablename.replace('\'', '\'\'')))
        if dbcursor.fetchone()[0] == 1:
            return True
        return False

    def close_dbconnection(self, connection, cursor):
        if (connection.is_connected()):
            cursor.close()
            connection.close()
            print("MySQL connection is closed")

    def create_DbTable(self):
        try:
            connection, cursor = self.initialise_dbconn()

            cursor.execute("SHOW DATABASES")

            if ('virustotal',) not in cursor.fetchall():
                cursor.execute("CREATE DATABASE virustotal;")
            else:
                cursor.execute("use virustotal;")
                cursor.execute("SELECT DATABASE();")
                print("Connected to: " + str(cursor.fetchall()[0]))

            if self.checkTableExists(cursor, 'VIRUSTOTAL'):
                print("Table exists already")
            else:
                mySql_Create_Table_Query = """CREATE TABLE IF NOT EXISTS VIRUSTOTAL (
                        md5 varchar(250) NOT NULL,
                        Detection_name varchar(250) NOT NULL,
                        positives int NOT NULL,
                        Scan_date Date NOT NULL,
                        PRIMARY KEY (md5)) """

                result = cursor.execute(mySql_Create_Table_Query)
                print("Virustotal Table created successfully ")


        except Error as e:
            print("Error while connecting to MySQL", e)

        finally:
            self.close_dbconnection(connection, cursor)

    def fetch_data(self, md5):
        try:
            connection, cursor = self.initialise_dbconn()
            md5_tuple = tuple(md5)
            sql_select_query = """select * from virustotal where md5 in {}""".format(md5_tuple)
            cursor.execute(sql_select_query)
            record = cursor.fetchall()
            print(record)

        except Error as e:
            print("Error while connecting to MySQL", e)

        finally:
            self.close_dbconnection(connection, cursor)

    def insert_data(self):
        try:
            connection, cursor = self.initialise_dbconn()

        except Error as e:
            print("Error while connecting to MySQL", e)

        finally:
            self.close_dbconnection(connection, cursor)