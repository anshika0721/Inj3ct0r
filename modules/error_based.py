#!/usr/bin/env python3

from typing import Dict, List, Optional, Tuple, Any
from core.request_engine import RequestEngine
from core.payload_manager import PayloadManager
import logging

class ErrorBasedInjector:
    def __init__(self, request_engine: RequestEngine, payload_manager: PayloadManager):
        """
        Initialize the ErrorBasedInjector.
        
        Args:
            request_engine: RequestEngine instance for making HTTP requests
            payload_manager: PayloadManager instance for managing SQL payloads
        """
        self.request_engine = request_engine
        self.payload_manager = payload_manager
        
        # Common SQL error messages to look for
        self.error_indicators = [
            "SQL syntax",
            "mysql_fetch_array",
            "ORA-",
            "PostgreSQL",
            "SQLite3::",
            "Warning: mysql_",
            "Microsoft SQL Server",
            "ODBC SQL Server Driver",
            "SQLite/JDBCDriver",
            "SQLite.Exception",
            "System.Data.SQLite.SQLiteException",
            "Warning: pg_",
            "PostgreSQL.*ERROR",
            "ERROR: syntax error at or near",
            "ERROR: unterminated quoted string at or near",
            "ERROR: column",
            "ERROR: relation",
            "ERROR: duplicate key value violates unique constraint",
            "ERROR: null value in column",
            "ERROR: current transaction is aborted",
            "ERROR: permission denied for",
            "ERROR: role",
            "ERROR: function",
            "ERROR: schema",
            "ERROR: database",
            "ERROR: relation",
            "ERROR: syntax error at end of input",
            "ERROR: syntax error at or near",
            "ERROR: unterminated quoted string at or near",
            "ERROR: unterminated quoted identifier at or near",
            "ERROR: unterminated /* comment at or near",
            "ERROR: unterminated -- comment at or near",
            "ERROR: unterminated /* comment at or near",
            "ERROR: unterminated -- comment at or near",
            "ERROR: unterminated quoted string at or near",
            "ERROR: unterminated quoted identifier at or near",
            "ERROR: unterminated /* comment at or near",
            "ERROR: unterminated -- comment at or near",
        ]
    
    def test_parameter(self, param_name: str, param_value: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Test a parameter for error-based SQL injection vulnerabilities.
        
        Args:
            param_name: Name of the parameter to test
            param_value: Original value of the parameter
            
        Returns:
            Tuple containing (is_vulnerable, payload, error_message)
        """
        logging.info(f"Testing parameter '{param_name}' for error-based SQL injection")
        
        for payload in self.payload_manager.get_payloads("error_based"):
            test_value = param_value + payload
            try:
                if self.request_engine.method == "GET":
                    params = {param_name: test_value}
                    response, _ = self.request_engine.send_request(params=params)
                else:
                    data = {param_name: test_value}
                    response, _ = self.request_engine.send_request(data=data)
                
                # Check for error messages in the response
                for indicator in self.error_indicators:
                    if indicator.lower() in response.text.lower():
                        logging.info(f"Found potential SQL injection with payload: {payload}")
                        return True, payload, indicator
                
            except Exception as e:
                logging.error(f"Error testing payload '{payload}': {str(e)}")
                continue
        
        return False, None, None
    
    def test_all_parameters(self) -> List[Dict]:
        """Test all parameters for error-based SQL injection vulnerabilities."""
        results = []
        params = self.request_engine.get_parameters()
        
        for param_name in params:
            # Test MySQL error-based injection
            mysql_results = self._test_mysql_error(param_name)
            results.extend(mysql_results)
            
            # Test PostgreSQL error-based injection
            postgres_results = self._test_postgres_error(param_name)
            results.extend(postgres_results)
            
            # Test MSSQL error-based injection
            mssql_results = self._test_mssql_error(param_name)
            results.extend(mssql_results)
        
        return results
    
    def _test_mysql_error(self, param_name: str) -> List[Dict]:
        """Test for MySQL error-based SQL injection."""
        results = []
        payloads = self.payload_manager.get_payloads("error", "mysql")
        
        for payload in payloads:
            try:
                # Send request with payload
                response, _ = self.request_engine.send_request(
                    payload=payload,
                    params={param_name: payload}
                )
                
                if not response:
                    continue
                
                # Check for MySQL error messages
                error_messages = [
                    "You have an error in your SQL syntax",
                    "check the manual that corresponds to your MySQL server version",
                    "MySQL server version",
                    "Warning: mysql_",
                    "valid MySQL result",
                    "check the manual that corresponds to your MariaDB server version",
                    "MySqlException"
                ]
                
                for error_msg in error_messages:
                    if error_msg in response.text:
                        results.append({
                            "type": "error",
                            "parameter": param_name,
                            "payload": payload,
                            "severity": "high",
                            "description": f"Error-based SQL injection detected in MySQL: {error_msg}"
                        })
                        break
            
            except Exception as e:
                logging.error(f"Error testing MySQL error-based injection: {str(e)}")
                continue
        
        return results
    
    def _test_postgres_error(self, param_name: str) -> List[Dict]:
        """Test for PostgreSQL error-based SQL injection."""
        results = []
        payloads = self.payload_manager.get_payloads("error", "postgresql")
        
        for payload in payloads:
            try:
                # Send request with payload
                response, _ = self.request_engine.send_request(
                    payload=payload,
                    params={param_name: payload}
                )
                
                if not response:
                    continue
                
                # Check for PostgreSQL error messages
                error_messages = [
                    "PostgreSQL",
                    "pg_",
                    "PSQLException",
                    "ERROR: syntax error at or near",
                    "ERROR: invalid input syntax for",
                    "ERROR: column",
                    "ERROR: relation",
                    "ERROR: function"
                ]
                
                for error_msg in error_messages:
                    if error_msg in response.text:
                        results.append({
                            "type": "error",
                            "parameter": param_name,
                            "payload": payload,
                            "severity": "high",
                            "description": f"Error-based SQL injection detected in PostgreSQL: {error_msg}"
                        })
                        break
            
            except Exception as e:
                logging.error(f"Error testing PostgreSQL error-based injection: {str(e)}")
                continue
        
        return results
    
    def _test_mssql_error(self, param_name: str) -> List[Dict]:
        """Test for MSSQL error-based SQL injection."""
        results = []
        payloads = self.payload_manager.get_payloads("error", "mssql")
        
        for payload in payloads:
            try:
                # Send request with payload
                response, _ = self.request_engine.send_request(
                    payload=payload,
                    params={param_name: payload}
                )
                
                if not response:
                    continue
                
                # Check for MSSQL error messages
                error_messages = [
                    "Microsoft SQL Server",
                    "SQLServer JDBC Driver",
                    "ODBC SQL Server Driver",
                    "SQLServerException",
                    "Warning: mssql_",
                    "Msg ",
                    "Incorrect syntax near"
                ]
                
                for error_msg in error_messages:
                    if error_msg in response.text:
                        results.append({
                            "type": "error",
                            "parameter": param_name,
                            "payload": payload,
                            "severity": "high",
                            "description": f"Error-based SQL injection detected in MSSQL: {error_msg}"
                        })
                        break
            
            except Exception as e:
                logging.error(f"Error testing MSSQL error-based injection: {str(e)}")
                continue
        
        return results
        
    def _check_mysql_error(self, response) -> bool:
        """Check if response contains MySQL error messages."""
        error_indicators = [
            "You have an error in your SQL syntax",
            "MySQL server version",
            "Warning: mysql_",
            "Warning: mysqli_",
            "Warning: PDO::",
            "SQL syntax.*MySQL",
            "Warning.*mysql_.*",
            "valid MySQL result",
            "check the manual that corresponds to your (MySQL|MariaDB) server version",
            r"MySqlException \(0x",
            "com.mysql.jdbc.exceptions",
            "MySQLSyntaxErrorException",
            "Unknown column",
            "Duplicate entry",
            "Table.*doesn't exist",
            "Unknown table",
            "Column count doesn't match"
        ]
        
        return self._check_error_indicators(response, error_indicators)
        
    def _check_postgres_error(self, response) -> bool:
        """Check if response contains PostgreSQL error messages."""
        error_indicators = [
            "PostgreSQL.*ERROR",
            "Warning.*pg_",
            "valid PostgreSQL result",
            "Npgsql.",
            "PG::SyntaxError:",
            "ERROR: syntax error at or near",
            "ERROR: parser: parse error at or near",
            "ERROR: invalid input syntax for",
            "ERROR: column.*does not exist",
            "ERROR: relation.*does not exist",
            "ERROR: duplicate key value violates unique constraint",
            "ERROR: null value in column.*violates not-null constraint"
        ]
        
        return self._check_error_indicators(response, error_indicators)
        
    def _check_mssql_error(self, response) -> bool:
        """Check if response contains MSSQL error messages."""
        error_indicators = [
            "SQLServer JDBC Driver",
            "com.microsoft.sqlserver.jdbc.SQLServerException",
            "ODBC SQL Server Driver",
            "Warning: mssql_",
            r"Msg \d+, Level \d+, State \d+",
            "Unclosed quotation mark after the character string",
            "Microsoft OLE DB Provider for SQL Server",
            "Microsoft SQL Server",
            "SQLServer JDBC Driver",
            r"ODBC Driver \d+ for SQL Server",
            "Warning: odbc_",
            "Microsoft SQL Server Native Client error",
            r"Msg \d+, Level \d+, State \d+",
            r"Line \d+: Incorrect syntax near",
            "Unclosed quotation mark after the character string",
            "Incorrect syntax near",
            "The multi-part identifier",
            "Could not find stored procedure",
            "Invalid column name",
            "Invalid object name"
        ]
        
        return self._check_error_indicators(response, error_indicators)
        
    def _check_error_indicators(self, response, indicators: List[str]) -> bool:
        """Check if response contains any of the error indicators."""
        response_text = response.text.lower()
        
        for indicator in indicators:
            if indicator.lower() in response_text:
                return True
                
        return False
        
    def _extract_mysql_error(self, response) -> str:
        """Extract MySQL error message from response."""
        error_indicators = [
            "You have an error in your SQL syntax",
            "MySQL server version",
            "Warning: mysql_",
            "Warning: mysqli_",
            "Warning: PDO::",
            "SQL syntax.*MySQL",
            "Warning.*mysql_.*",
            "valid MySQL result",
            "check the manual that corresponds to your (MySQL|MariaDB) server version",
            r"MySqlException \(0x",
            "com.mysql.jdbc.exceptions",
            "MySQLSyntaxErrorException",
            "Unknown column",
            "Duplicate entry",
            "Table.*doesn't exist",
            "Unknown table",
            "Column count doesn't match"
        ]
        
        return self._extract_error_message(response, error_indicators)
        
    def _extract_postgres_error(self, response) -> str:
        """Extract PostgreSQL error message from response."""
        error_indicators = [
            "PostgreSQL.*ERROR",
            "Warning.*pg_",
            "valid PostgreSQL result",
            "Npgsql.",
            "PG::SyntaxError:",
            "ERROR: syntax error at or near",
            "ERROR: parser: parse error at or near",
            "ERROR: invalid input syntax for",
            "ERROR: column.*does not exist",
            "ERROR: relation.*does not exist",
            "ERROR: duplicate key value violates unique constraint",
            "ERROR: null value in column.*violates not-null constraint"
        ]
        
        return self._extract_error_message(response, error_indicators)
        
    def _extract_mssql_error(self, response) -> str:
        """Extract MSSQL error message from response."""
        error_indicators = [
            "SQLServer JDBC Driver",
            "com.microsoft.sqlserver.jdbc.SQLServerException",
            "ODBC SQL Server Driver",
            "Warning: mssql_",
            r"Msg \d+, Level \d+, State \d+",
            "Unclosed quotation mark after the character string",
            "Microsoft OLE DB Provider for SQL Server",
            "Microsoft SQL Server",
            "SQLServer JDBC Driver",
            r"ODBC Driver \d+ for SQL Server",
            "Warning: odbc_",
            "Microsoft SQL Server Native Client error",
            r"Msg \d+, Level \d+, State \d+",
            r"Line \d+: Incorrect syntax near",
            "Unclosed quotation mark after the character string",
            "Incorrect syntax near",
            "The multi-part identifier",
            "Could not find stored procedure",
            "Invalid column name",
            "Invalid object name"
        ]
        
        return self._extract_error_message(response, error_indicators)
        
    def _extract_error_message(self, response, indicators: List[str]) -> str:
        """Extract error message from response using indicators."""
        response_text = response.text
        
        for indicator in indicators:
            if indicator.lower() in response_text.lower():
                # Try to extract the full error message
                start = response_text.lower().find(indicator.lower())
                if start != -1:
                    # Get the next few lines after the error
                    lines = response_text[start:].split('\n')[:3]
                    return ' '.join(lines).strip()
                    
        return "Unknown error" 
