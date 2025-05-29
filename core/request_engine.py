#!/usr/bin/env python3

import requests
from urllib.parse import urlparse, parse_qs
from typing import Dict, Optional, Union, Tuple
import logging
import time

class RequestEngine:
    def __init__(self, 
                 url: str,
                 method: str = "GET",
                 headers: Optional[Dict] = None,
                 cookies: Optional[Dict] = None,
                 proxy: Optional[Dict] = None,
                 timeout: int = 30,
                 verify_ssl: bool = True):
        """
        Initialize the RequestEngine with target URL and request parameters.
        
        Args:0
            url: Target URL
            method: HTTP method (GET or POST)
            headers: Custom HTTP headers
            cookies: Custom cookies
            proxy: Proxy configuration
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.url = url
        self.method = method.upper()
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.proxy = proxy
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        
        # Set default headers if none provided
        if not self.headers:
            self.headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
    
    def send_request(self, 
                    params: Optional[Dict] = None,
                    data: Optional[Dict] = None,
                    json_data: Optional[Dict] = None) -> Tuple[requests.Response, float]:
        """
        Send an HTTP request and return the response with timing information.
        
        Args:
            params: URL parameters for GET requests
            data: Form data for POST requests
            json_data: JSON data for POST requests
            
        Returns:
            Tuple containing (response object, response time in seconds)
        """
        try:
            start_time = time.time()
            
            if self.method == "GET":
                response = self.session.get(
                    self.url,
                    params=params,
                    headers=self.headers,
                    cookies=self.cookies,
                    proxies=self.proxy,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
            else:  # POST
                response = self.session.post(
                    self.url,
                    params=params,
                    data=data,
                    json=json_data,
                    headers=self.headers,
                    cookies=self.cookies,
                    proxies=self.proxy,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
            
            end_time = time.time()
            response_time = end_time - start_time
            
            return response, response_time
            
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed: {str(e)}")
            raise
    
    def get_url_parameters(self) -> Dict[str, str]:
        """
        Extract and return URL parameters from the target URL.
        
        Returns:
            Dictionary of parameter names and values
        """
        parsed_url = urlparse(self.url)
        params = parse_qs(parsed_url.query)
        return {k: v[0] for k, v in params.items()}
    
    def update_headers(self, headers: Dict[str, str]) -> None:
        """
        Update the request headers.
        
        Args:
            headers: New headers to add/update
        """
        self.headers.update(headers)
    
    def update_cookies(self, cookies: Dict[str, str]) -> None:
        """
        Update the request cookies.
        
        Args:
            cookies: New cookies to add/update
        """
        self.cookies.update(cookies)
    
    def set_proxy(self, proxy: Dict[str, str]) -> None:
        """
        Set or update the proxy configuration.
        
        Args:
            proxy: Proxy configuration (e.g., {"http": "http://proxy:port"})
        """
        self.proxy = proxy 
