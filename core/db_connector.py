import logging
from typing import Dict, List, Any, Optional, Tuple
import mysql.connector
import psycopg2
import pymssql
import sqlite3

class DatabaseConnector:
    def __init__(self, dbms: str, host: str, port: int, database: str,
                 username: str, password: str):
        self.dbms = dbms.lower()
        self.host = host
        self.port = port
        self.database = database
        self.username = username
        self.password = password
        self.connection = None
        self.cursor = None
        
    def connect(self) -> bool:
        """Establish database connection."""
        try:
            if self.dbms == "mysql":
                self.connection = mysql.connector.connect(
                    host=self.host,
                    port=self.port,
                    database=self.database,
                    user=self.username,
                    password=self.password
                )
            elif self.dbms == "postgresql":
                self.connection = psycopg2.connect(
                    host=self.host,
                    port=self.port,
                    database=self.database,
                    user=self.username,
                    password=self.password
                )
            elif self.dbms == "mssql":
                self.connection = pymssql.connect(
                    server=self.host,
                    port=self.port,
                    database=self.database,
                    user=self.username,
                    password=self.password
                )
            elif self.dbms == "sqlite":
                self.connection = sqlite3.connect(self.database)
            else:
                logging.error(f"Unsupported DBMS: {self.dbms}")
                return False
                
            self.cursor = self.connection.cursor()
            return True
            
        except Exception as e:
            logging.error(f"Database connection failed: {str(e)}")
            return False
            
    def disconnect(self) -> None:
        """Close database connection."""
        try:
            if self.cursor:
                self.cursor.close()
            if self.connection:
                self.connection.close()
        except Exception as e:
            logging.error(f"Error closing database connection: {str(e)}")
            
    def execute_query(self, query: str, params: Optional[Tuple] = None) -> Tuple[bool, Optional[List[Any]]]:
        """Execute SQL query and return results."""
        try:
            if not self.connection or not self.cursor:
                if not self.connect():
                    return False, None
                    
            self.cursor.execute(query, params or ())
            
            if query.strip().upper().startswith(("SELECT", "SHOW", "DESCRIBE", "EXPLAIN")):
                results = self.cursor.fetchall()
                return True, results
            else:
                self.connection.commit()
                return True, None
                
        except Exception as e:
            logging.error(f"Query execution failed: {str(e)}")
            return False, None
            
    def get_tables(self) -> List[str]:
        """Get list of tables in the database."""
        try:
            if self.dbms == "mysql":
                query = "SHOW TABLES"
            elif self.dbms == "postgresql":
                query = "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
            elif self.dbms == "mssql":
                query = "SELECT name FROM sys.tables"
            elif self.dbms == "sqlite":
                query = "SELECT name FROM sqlite_master WHERE type='table'"
            else:
                return []
                
            success, results = self.execute_query(query)
            if success and results:
                return [row[0] for row in results]
            return []
            
        except Exception as e:
            logging.error(f"Error getting tables: {str(e)}")
            return []
            
    def get_columns(self, table: str) -> List[Dict[str, str]]:
        """Get list of columns in a table."""
        try:
            if self.dbms == "mysql":
                query = f"SHOW COLUMNS FROM {table}"
            elif self.dbms == "postgresql":
                query = f"""
                    SELECT column_name, data_type, character_maximum_length
                    FROM information_schema.columns
                    WHERE table_name = %s
                """
            elif self.dbms == "mssql":
                query = f"""
                    SELECT name, system_type_name, max_length
                    FROM sys.columns
                    WHERE object_id = OBJECT_ID(%s)
                """
            elif self.dbms == "sqlite":
                query = f"PRAGMA table_info({table})"
            else:
                return []
                
            success, results = self.execute_query(query, (table,) if self.dbms in ["postgresql", "mssql"] else None)
            if not success or not results:
                return []
                
            columns = []
            for row in results:
                if self.dbms == "mysql":
                    columns.append({
                        "name": row[0],
                        "type": row[1],
                        "length": row[2] if len(row) > 2 else None
                    })
                elif self.dbms == "postgresql":
                    columns.append({
                        "name": row[0],
                        "type": row[1],
                        "length": row[2]
                    })
                elif self.dbms == "mssql":
                    columns.append({
                        "name": row[0],
                        "type": row[1],
                        "length": row[2]
                    })
                elif self.dbms == "sqlite":
                    columns.append({
                        "name": row[1],
                        "type": row[2],
                        "length": None
                    })
                    
            return columns
            
        except Exception as e:
            logging.error(f"Error getting columns: {str(e)}")
            return []
            
    def get_table_data(self, table: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get sample data from a table."""
        try:
            query = f"SELECT * FROM {table} LIMIT {limit}"
            success, results = self.execute_query(query)
            
            if not success or not results:
                return []
                
            columns = self.get_columns(table)
            if not columns:
                return []
                
            data = []
            for row in results:
                row_data = {}
                for i, col in enumerate(columns):
                    if i < len(row):
                        row_data[col["name"]] = row[i]
                data.append(row_data)
                
            return data
            
        except Exception as e:
            logging.error(f"Error getting table data: {str(e)}")
            return []
            
    def get_database_info(self) -> Dict[str, Any]:
        """Get database information."""
        try:
            info = {
                "dbms": self.dbms,
                "host": self.host,
                "port": self.port,
                "database": self.database,
                "username": self.username,
                "version": None,
                "tables": self.get_tables()
            }
            
            # Get version
            if self.dbms == "mysql":
                success, results = self.execute_query("SELECT VERSION()")
            elif self.dbms == "postgresql":
                success, results = self.execute_query("SELECT version()")
            elif self.dbms == "mssql":
                success, results = self.execute_query("SELECT @@version")
            elif self.dbms == "sqlite":
                success, results = self.execute_query("SELECT sqlite_version()")
            else:
                success, results = False, None
                
            if success and results:
                info["version"] = results[0][0]
                
            return info
            
        except Exception as e:
            logging.error(f"Error getting database info: {str(e)}")
            return {
                "dbms": self.dbms,
                "host": self.host,
                "port": self.port,
                "database": self.database,
                "username": self.username,
                "version": None,
                "tables": []
            } 
