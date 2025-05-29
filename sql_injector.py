#!/usr/bin/env python3

import argparse
import json
import logging
from typing import Dict, Optional
from core.request_engine import RequestEngine
from core.payload_manager import PayloadManager
from modules.error_based import ErrorBasedInjector
from utils.helpers import (
    setup_logging,
    parse_json_input,
    format_output,
    detect_waf,
    sanitize_output,
    print_banner
)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Advanced SQL Injection Testing Tool")
    
    # Required arguments
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    
    # Optional arguments
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"],
                      help="HTTP method (default: GET)")
    parser.add_argument("-H", "--headers", help="Custom headers (JSON format)")
    parser.add_argument("-c", "--cookies", help="Custom cookies (JSON format)")
    parser.add_argument("-d", "--data", help="POST data (JSON format)")
    parser.add_argument("-p", "--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-f", "--format", choices=["text", "json"], default="text",
                      help="Output format (default: text)")
    parser.add_argument("-v", "--verbose", action="store_true",
                      help="Enable verbose output")
    parser.add_argument("--timeout", type=int, default=30,
                      help="Request timeout in seconds (default: 30)")
    parser.add_argument("--no-ssl-verify", action="store_true",
                      help="Disable SSL certificate verification")
    parser.add_argument("--payload-file", help="Custom payload file (JSON format)")
    
    return parser.parse_args()

def main():
    """Main function."""
    # Parse arguments
    args = parse_arguments()
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Print banner
    print_banner()
    
    try:
        # Parse JSON inputs
        headers = parse_json_input(args.headers) if args.headers else {}
        cookies = parse_json_input(args.cookies) if args.cookies else {}
        data = parse_json_input(args.data) if args.data else {}
        
        # Setup proxy if provided
        proxy = {"http": args.proxy, "https": args.proxy} if args.proxy else None
        
        # Initialize components
        request_engine = RequestEngine(
            url=args.url,
            method=args.method,
            headers=headers,
            cookies=cookies,
            proxy=proxy,
            timeout=args.timeout,
            verify_ssl=not args.no_ssl_verify
        )
        
        payload_manager = PayloadManager(args.payload_file)
        error_injector = ErrorBasedInjector(request_engine, payload_manager)
        
        # Run tests
        logging.info(f"Starting SQL injection tests on: {args.url}")
        
        # Check for WAF
        response, _ = request_engine.send_request()
        waf = detect_waf(response.text)
        if waf:
            logging.warning(f"Web Application Firewall detected: {waf}")
        
        # Run error-based tests
        results = error_injector.test_all_parameters()
        
        # Format and output results
        output = format_output(results, args.format)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
        else:
            print(output)
        
    except KeyboardInterrupt:
        logging.info("\nTest interrupted by user")
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        if args.verbose:
            logging.exception("Detailed error information:")

if __name__ == "__main__":
    main() 
