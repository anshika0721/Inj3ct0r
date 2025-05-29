#!/usr/bin/env python3

import re
import json
from typing import Dict, List, Optional, Union
from urllib.parse import urlparse, parse_qs
import logging
from colorama import Fore, Style

def setup_logging(verbose: bool = False) -> None:
    """
    Set up logging configuration.
    
    Args:
        verbose: Whether to enable verbose logging
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def parse_json_input(json_str: str) -> Dict:
    """
    Parse JSON input string safely.
    
    Args:
        json_str: JSON string to parse
        
    Returns:
        Parsed JSON as dictionary
    """
    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing JSON: {str(e)}")
        return {}

def extract_parameters(url: str) -> Dict[str, str]:
    """
    Extract parameters from a URL.
    
    Args:
        url: URL to extract parameters from
        
    Returns:
        Dictionary of parameter names and values
    """
    try:
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        return {k: v[0] for k, v in params.items()}
    except Exception as e:
        logging.error(f"Error extracting parameters: {str(e)}")
        return {}

def format_output(results: Dict, output_format: str = "text") -> str:
    """
    Format test results for output.
    
    Args:
        results: Dictionary of test results
        output_format: Output format (text or json)
        
    Returns:
        Formatted output string
    """
    if output_format == "json":
        return json.dumps(results, indent=4)
    
    output = []
    for param_name, (is_vulnerable, payload, error_msg) in results.items():
        if is_vulnerable:
            output.append(f"{Fore.GREEN}[+] Parameter '{param_name}' is vulnerable to SQL injection{Style.RESET_ALL}")
            output.append(f"    Payload: {payload}")
            output.append(f"    Error: {error_msg}")
        else:
            output.append(f"{Fore.YELLOW}[-] Parameter '{param_name}' appears to be safe{Style.RESET_ALL}")
    
    return "\n".join(output)

def detect_waf(response_text: str) -> Optional[str]:
    """
    Detect presence of Web Application Firewall (WAF).
    
    Args:
        response_text: Response text to analyze
        
    Returns:
        WAF name if detected, None otherwise
    """
    waf_indicators = {
        "ModSecurity": [
            "ModSecurity",
            "Mod_Security",
            "NOYB",
        ],
        "Cloudflare": [
            "Cloudflare",
            "Ray ID:",
            "cf-ray",
        ],
        "Akamai": [
            "AkamaiGHost",
            "Akamai",
        ],
        "Imperva": [
            "Incapsula",
            "Imperva",
        ],
        "F5": [
            "F5-TrafficShield",
            "F5 BIG-IP",
        ],
    }
    
    for waf_name, indicators in waf_indicators.items():
        for indicator in indicators:
            if indicator.lower() in response_text.lower():
                return waf_name
    
    return None

def sanitize_output(text: str) -> str:
    """
    Sanitize output text by removing sensitive information.
    
    Args:
        text: Text to sanitize
        
    Returns:
        Sanitized text
    """
    # Remove potential sensitive data
    patterns = [
        r'password\s*=\s*[^\s&]+',
        r'passwd\s*=\s*[^\s&]+',
        r'pwd\s*=\s*[^\s&]+',
        r'secret\s*=\s*[^\s&]+',
        r'key\s*=\s*[^\s&]+',
        r'token\s*=\s*[^\s&]+',
    ]
    
    for pattern in patterns:
        text = re.sub(pattern, '***REDACTED***', text, flags=re.IGNORECASE)
    
    return text

def print_banner() -> None:
    """
    Print the tool's banner.
    """
    banner = f"""
{Fore.CYAN}╔════════════════════════════════════════════════════════════╗
║                                                                ║
║  {Fore.RED}SQL Injection Testing Tool{Fore.CYAN}                              ║
║  {Fore.YELLOW}Advanced SQL Injection Detection and Exploitation{Fore.CYAN}        ║
║                                                                ║
╚════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner) 
