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
        
        # Parse URL and get parameters
        parsed_url = urlparse(url)
        self.params = parse_qs(parsed_url.query)
        self.params = {k: v[0] for k, v in self.params.items()}
        
        # Set default headers if not provided
        if "User-Agent" not in self.headers:
            self.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    
    def send_request(self, payload: Optional[str] = None, params: Optional[Dict[str, str]] = None, data: Optional[Dict[str, Any]] = None) -> Tuple[requests.Response, float]:
        """Send a request with optional payload and parameters."""
        try:
            # Prepare request data
            request_params = self.params.copy()
            request_data = self.data.copy()
            
            # Update with provided parameters and data
            if params:
                request_params.update(params)
            if data:
                request_data.update(data)
                
            # Add payload if provided
            if payload:
                if self.method == "GET":
                    # For GET requests, add payload to parameters
                    for param in request_params:
                        request_params[param] = request_params[param] + payload if request_params[param] else payload
                else:
                    # For POST requests, add payload to data
                    for param in request_data:
                        request_data[param] = request_data[param] + payload if request_data[param] else payload
            
            # Send request based on method
            start_time = time.time()
            if self.method == "GET":
                response = requests.get(
                    self.url,
                    params=request_params,
                    headers=self.headers,
                    cookies=self.cookies,
                    timeout=self.timeout,
                    verify=False
                )
            else:  # POST
                response = requests.post(
                    self.url,
                    params=request_params,
                    data=request_data,
                    headers=self.headers,
                    cookies=self.cookies,
                    timeout=self.timeout,
                    verify=False
                )
            end_time = time.time()
            
            return response, end_time - start_time
            
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed: {str(e)}")
            raise
    
    def get_url_parameters(self) -> Dict[str, str]:
        """Get URL parameters."""
        return self.params
    
    def get_parameters(self) -> Dict[str, str]:
        """Get all parameters (URL parameters and POST data)."""
        params = self.params.copy()
        if self.method == "POST" and self.data:
            params.update(self.data)
        return params
    
    def update_url_parameters(self, params: Dict[str, str]) -> None:
        """Update URL parameters."""
        self.params.update(params)
        
        # Reconstruct URL with updated parameters
        parsed_url = urlparse(self.url)
        new_query = urlencode(self.params, doseq=True)
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
