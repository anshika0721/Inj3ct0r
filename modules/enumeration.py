import logging
from typing import List, Dict, Any
from core.request_engine import RequestEngine
from core.payload_manager import PayloadManager

class DatabaseEnumerator:
    def __init__(self, request_engine: RequestEngine, payload_manager: PayloadManager):
        self.request_engine = request_engine
        self.payload_manager = payload_manager
        self.dbms = None
        
    def set_dbms(self, dbms: str):
        """Set the target DBMS."""
        self.dbms = dbms
        logging.info(f"Target DBMS set to: {dbms}")
        
    def enumerate_tables(self) -> List[Dict[str, Any]]:
        """Enumerate database tables."""
        if not self.dbms:
            logging.error("DBMS not set. Use --dbms to specify the target database.")
            return []
            
        results = []
        try:
            # Get all databases first
            databases = self._get_databases()
            results.append({
                "type": "databases",
                "data": databases
            })
            
            # For each database, get its tables
            for db in databases:
                tables = self._get_tables(db)
                results.append({
                    "type": "tables",
                    "database": db,
                    "data": tables
                })
                
        except Exception as e:
            logging.error(f"Error enumerating tables: {str(e)}")
            
        return results
        
    def enumerate_columns(self) -> List[Dict[str, Any]]:
        """Enumerate table columns."""
        if not self.dbms:
            logging.error("DBMS not set. Use --dbms to specify the target database.")
            return []
            
        results = []
        try:
            # Get all databases
            databases = self._get_databases()
            
            # For each database, get its tables
            for db in databases:
                tables = self._get_tables(db)
                
                # For each table, get its columns
                for table in tables:
                    columns = self._get_columns(db, table)
                    results.append({
                        "type": "columns",
                        "database": db,
                        "table": table,
                        "data": columns
                    })
                    
        except Exception as e:
            logging.error(f"Error enumerating columns: {str(e)}")
            
        return results
        
    def _get_databases(self) -> List[str]:
        """Get list of all databases."""
        if self.dbms == "MySQL":
            payload = "SELECT schema_name FROM information_schema.schemata"
        elif self.dbms == "PostgreSQL":
            payload = "SELECT datname FROM pg_database"
        elif self.dbms == "MSSQL":
            payload = "SELECT name FROM master.dbo.sysdatabases"
        else:
            return []
            
        response, _ = self.request_engine.send_request(payload=payload)
        return response.text.split('\n')
        
    def _get_tables(self, database: str) -> List[str]:
        """Get list of tables in a database."""
        if self.dbms == "MySQL":
            payload = f"SELECT table_name FROM information_schema.tables WHERE table_schema='{database}'"
        elif self.dbms == "PostgreSQL":
            payload = f"SELECT tablename FROM pg_tables WHERE schemaname='{database}'"
        elif self.dbms == "MSSQL":
            payload = f"SELECT name FROM {database}.dbo.sysobjects WHERE xtype='U'"
        else:
            return []
            
        response, _ = self.request_engine.send_request(payload=payload)
        return response.text.split('\n')
        
    def _get_columns(self, database: str, table: str) -> List[Dict[str, str]]:
        """Get list of columns in a table."""
        if self.dbms == "MySQL":
            payload = f"""
            SELECT column_name, data_type, column_type 
            FROM information_schema.columns 
            WHERE table_schema='{database}' AND table_name='{table}'
            """
        elif self.dbms == "PostgreSQL":
            payload = f"""
            SELECT column_name, data_type, character_maximum_length 
            FROM information_schema.columns 
            WHERE table_schema='{database}' AND table_name='{table}'
            """
        elif self.dbms == "MSSQL":
            payload = f"""
            SELECT name, type_name(xtype), length 
            FROM {database}.dbo.syscolumns 
            WHERE id=OBJECT_ID('{database}.dbo.{table}')
            """
        else:
            return []
            
        response, _ = self.request_engine.send_request(payload=payload)
        return self._parse_columns(response.text)
        
    def _parse_columns(self, response_text: str) -> List[Dict[str, str]]:
        """Parse column information from response."""
        columns = []
        try:
            # Split response into lines and parse each line
            lines = response_text.strip().split('\n')
            for line in lines:
                parts = line.split('\t')
                if len(parts) >= 2:
                    columns.append({
                        "name": parts[0],
                        "type": parts[1],
                        "length": parts[2] if len(parts) > 2 else None
                    })
        except Exception as e:
            logging.error(f"Error parsing columns: {str(e)}")
            
        return columns
        
    def get_table_data(self, database: str, table: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get sample data from a table."""
        try:
            payload = f"SELECT * FROM {database}.{table} LIMIT {limit}"
            response, _ = self.request_engine.send_request(payload=payload)
            
            return [{
                "type": "table_data",
                "database": database,
                "table": table,
                "data": response.text.split('\n')
            }]
            
        except Exception as e:
            logging.error(f"Error getting table data: {str(e)}")
            return []
            
    def get_database_info(self) -> Dict[str, Any]:
        """Get detailed database information."""
        if not self.dbms:
            return {}
            
        try:
            info = {
                "version": self._get_version(),
                "user": self._get_current_user(),
                "hostname": self._get_hostname(),
                "databases": self._get_databases()
            }
            
            return {
                "type": "database_info",
                "data": info
            }
            
        except Exception as e:
            logging.error(f"Error getting database info: {str(e)}")
            return {}
            
    def _get_version(self) -> str:
        """Get database version."""
        if self.dbms == "MySQL":
            payload = "SELECT VERSION()"
        elif self.dbms == "PostgreSQL":
            payload = "SELECT version()"
        elif self.dbms == "MSSQL":
            payload = "SELECT @@version"
        else:
            return "Unknown"
            
        response, _ = self.request_engine.send_request(payload=payload)
        return response.text
        
    def _get_current_user(self) -> str:
        """Get current database user."""
        if self.dbms == "MySQL":
            payload = "SELECT CURRENT_USER()"
        elif self.dbms == "PostgreSQL":
            payload = "SELECT current_user"
        elif self.dbms == "MSSQL":
            payload = "SELECT SYSTEM_USER"
        else:
            return "Unknown"
            
        response, _ = self.request_engine.send_request(payload=payload)
        return response.text
        
    def _get_hostname(self) -> str:
        """Get database hostname."""
        if self.dbms == "MySQL":
            payload = "SELECT @@hostname"
        elif self.dbms == "PostgreSQL":
            payload = "SELECT inet_server_addr()"
        elif self.dbms == "MSSQL":
            payload = "SELECT HOST_NAME()"
        else:
            return "Unknown"
            
        response, _ = self.request_engine.send_request(payload=payload)
        return response.text 
