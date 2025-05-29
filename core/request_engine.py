#!/usr/bin/env python3

import requests
from urllib.parse import urlparse, parse_qs, urlencode
from typing import Dict, Optional, Tuple, Any
import logging
import time

class RequestEngine:
    def __init__(self, url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None,
                 cookies: Optional[Dict[str, str]] = None, data: Optional[Dict[str, Any]] = None,
                 timeout: int = 10, verify_ssl: bool = True):
        """
        Initialize the RequestEngine with target URL and request parameters.
        
        Args:
            url: Target URL
            method: HTTP method (GET or POST)
            headers: Custom HTTP headers
            cookies: Custom cookies
            data: Form data for POST requests
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.url = url
        self.method = method.upper()
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.data = data or {}
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        
        # Set default headers if not provided
        if "User-Agent" not in self.headers:
            self.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    
    def send_request(self, payload: Optional[str] = None) -> Tuple[requests.Response, Dict[str, Any]]:
        """Send HTTP request with optional payload."""
        try:
            # Parse URL and get parameters
            parsed_url = urlparse(self.url)
            params = parse_qs(parsed_url.query)
            
            # Prepare request data
            request_data = {
                "url": self.url,
                "headers": self.headers,
                "cookies": self.cookies,
                "timeout": self.timeout,
                "verify": self.verify_ssl
            }
            
            # Handle payload injection
            if payload:
                if self.method == "GET":
                    # Inject payload into URL parameters
                    for param in params:
                        params[param] = [payload]
                    request_data["params"] = params
                elif self.method == "POST":
                    # Inject payload into POST data
                    request_data["data"] = {k: payload for k in self.data}
                else:
                    logging.warning(f"Unsupported HTTP method: {self.method}")
                    return None, {}
                    
            # Send request
            if self.method == "GET":
                response = self.session.get(**request_data)
            elif self.method == "POST":
                response = self.session.post(**request_data)
            else:
                logging.warning(f"Unsupported HTTP method: {self.method}")
                return None, {}
                
            # Prepare response info
            response_info = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "cookies": dict(response.cookies),
                "elapsed": response.elapsed.total_seconds(),
                "content_length": len(response.content)
            }
            
            return response, response_info
            
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed: {str(e)}")
            return None, {}
    
    def get_url_parameters(self) -> Dict[str, str]:
        """Get URL parameters."""
        parsed_url = urlparse(self.url)
        params = parse_qs(parsed_url.query)
        return {k: v[0] for k, v in params.items()}
    
    def update_url_parameters(self, params: Dict[str, str]) -> None:
        """Update URL parameters."""
        parsed_url = urlparse(self.url)
        current_params = parse_qs(parsed_url.query)
        current_params.update({k: [v] for k, v in params.items()})
        
        # Reconstruct URL with updated parameters
        new_query = urlencode(current_params, doseq=True)
        self.url = parsed_url._replace(query=new_query).geturl()
    
    def update_headers(self, headers: Dict[str, str]) -> None:
        """Update request headers."""
        self.headers.update(headers)
    
    def update_cookies(self, cookies: Dict[str, str]) -> None:
        """Update request cookies."""
        self.cookies.update(cookies)
    
    def update_data(self, data: Dict[str, Any]) -> None:
        """Update request data."""
        self.data.update(data)
    
    def set_method(self, method: str) -> None:
        """Set HTTP method."""
        self.method = method.upper()
    
    def set_timeout(self, timeout: int) -> None:
        """Set request timeout."""
        self.timeout = timeout
    
    def set_verify_ssl(self, verify: bool) -> None:
        """Set SSL verification."""
        self.verify_ssl = verify
    
    def close(self) -> None:
        """Close the session."""
        self.session.close() 
