#!/usr/bin/env python3

import re
from typing import Dict, Any, List
import logging
from .request_engine import RequestEngine

class DatabaseFingerprinter:
    def __init__(self):
        """Initialize database fingerprinter with common database signatures."""
        self.db_signatures = {
            "mysql": [
                r"mysql",
                r"you have an error in your sql syntax",
                r"warning: mysql_",
                r"valid mysql result",
                r"check the manual that corresponds to your (mysql|mariadb) server version"
            ],
            "postgresql": [
                r"postgresql",
                r"pg_",
                r"postgres",
                r"psql",
                r"valid postgresql result"
            ],
            "mssql": [
                r"microsoft sql server",
                r"sql server",
                r"mssql",
                r"valid mssql result",
                r"odbc sql server driver"
            ]
        }
        
        self.version_patterns = {
            "mysql": r"mysql.*?(\d+\.\d+\.\d+)",
            "postgresql": r"postgresql.*?(\d+\.\d+)",
            "mssql": r"microsoft sql server.*?(\d+\.\d+\.\d+)"
        }
        
    def fingerprint(self, request_engine: RequestEngine) -> Dict[str, Any]:
        """Detect database type and version."""
        try:
            # Test payloads for version detection
            version_payloads = {
                "mysql": "' UNION SELECT version() --",
                "postgresql": "' UNION SELECT version() --",
                "mssql": "' UNION SELECT @@version --"
            }
            
            detected_db = None
            version = None
            
            # Try each database type
            for db_type, payload in version_payloads.items():
                response, _ = request_engine.send_request(payload=payload)
                
                if not response:
                    continue
                    
                # Check for database signatures
                body = response.text.lower()
                for signature in self.db_signatures[db_type]:
                    if re.search(signature, body):
                        detected_db = db_type
                        break
                        
                # Try to extract version
                if detected_db:
                    version_match = re.search(self.version_patterns[db_type], body)
                    if version_match:
                        version = version_match.group(1)
                    break
                    
            return {
                "detected": detected_db is not None,
                "type": detected_db or "unknown",
                "version": version
            }
            
        except Exception as e:
            logging.error(f"Database fingerprinting failed: {str(e)}")
            return {"detected": False, "type": "unknown", "version": None} 
