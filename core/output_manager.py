import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

class OutputManager:
    def __init__(self, output_file: str = "results.json", format: str = "json"):
        """Initialize output manager."""
        self.output_file = output_file
        self.format = format
        self.results = {
            "scan_info": {
                "start_time": None,
                "end_time": None,
                "target": None,
                "techniques": []
            },
            "vulnerabilities": [],
            "waf_info": None,
            "database_info": None,
            "statistics": {
                "total_tests": 0,
                "successful_tests": 0,
                "failed_tests": 0,
                "vulnerabilities_found": 0
            }
        }
        
    def start_scan(self, target: str, techniques: List[str]) -> None:
        """Start scan and initialize results."""
        self.results["scan_info"]["start_time"] = datetime.now().isoformat()
        self.results["scan_info"]["target"] = target
        self.results["scan_info"]["techniques"] = techniques
        
    def end_scan(self) -> None:
        """End scan and finalize results."""
        self.results["scan_info"]["end_time"] = datetime.now().isoformat()
        
    def add_vulnerability(self, vuln_type: str, details: Dict[str, Any]) -> None:
        """Add vulnerability to results."""
        vulnerability = {
            "type": vuln_type,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
        self.results["vulnerabilities"].append(vulnerability)
        self.results["statistics"]["vulnerabilities_found"] += 1
        
    def set_waf_info(self, waf_info: Dict[str, Any]) -> None:
        """Set WAF information in results."""
        self.results["waf_info"] = waf_info
        
    def set_database_info(self, db_info: Dict[str, Any]) -> None:
        """Set database information in results."""
        self.results["database_info"] = db_info
        
    def update_statistics(self, total: int, successful: int, failed: int) -> None:
        """Update scan statistics."""
        self.results["statistics"]["total_tests"] = total
        self.results["statistics"]["successful_tests"] = successful
        self.results["statistics"]["failed_tests"] = failed
        
    def get_results(self) -> Dict[str, Any]:
        """Get current results."""
        return self.results
        
    def save_results(self) -> None:
        """Save results to file."""
        # Create output directory if it doesn't exist
        output_dir = os.path.dirname(self.output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        if self.format == "json":
            self._save_json()
        elif self.format == "html":
            self._save_html()
        elif self.format == "txt":
            self._save_txt()
        else:
            raise ValueError(f"Unsupported output format: {self.format}")
            
    def _save_json(self) -> None:
        """Save results in JSON format."""
        with open(self.output_file, 'w') as f:
            json.dump(self.results, f, indent=4)
            
    def _save_html(self) -> None:
        """Save results in HTML format."""
        html = self._generate_html()
        with open(self.output_file, 'w') as f:
            f.write(html)
            
    def _save_txt(self) -> None:
        """Save results in text format."""
        text = self._generate_text()
        with open(self.output_file, 'w') as f:
            f.write(text)
            
    def _generate_html(self) -> str:
        """Generate HTML report."""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SQL Injection Scan Results</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .section {{ margin-bottom: 20px; }}
                .vulnerability {{ background-color: #fff3f3; padding: 10px; margin: 5px 0; }}
                .statistics {{ background-color: #f5f5f5; padding: 10px; }}
                .success {{ color: green; }}
                .failure {{ color: red; }}
            </style>
        </head>
        <body>
            <h1>SQL Injection Scan Results</h1>
            
            <div class="section">
                <h2>Scan Information</h2>
                <p>Target: {self.results['scan_info']['target']}</p>
                <p>Start Time: {self.results['scan_info']['start_time']}</p>
                <p>End Time: {self.results['scan_info']['end_time']}</p>
                <p>Techniques: {', '.join(self.results['scan_info']['techniques'])}</p>
            </div>
            
            <div class="section">
                <h2>Statistics</h2>
                <div class="statistics">
                    <p>Total Tests: {self.results['statistics']['total_tests']}</p>
                    <p class="success">Successful Tests: {self.results['statistics']['successful_tests']}</p>
                    <p class="failure">Failed Tests: {self.results['statistics']['failed_tests']}</p>
                    <p>Vulnerabilities Found: {self.results['statistics']['vulnerabilities_found']}</p>
                </div>
            </div>
        """
        
        if self.results["waf_info"]:
            html += f"""
            <div class="section">
                <h2>WAF Information</h2>
                <pre>{json.dumps(self.results['waf_info'], indent=2)}</pre>
            </div>
            """
            
        if self.results["database_info"]:
            html += f"""
            <div class="section">
                <h2>Database Information</h2>
                <pre>{json.dumps(self.results['database_info'], indent=2)}</pre>
            </div>
            """
            
        if self.results["vulnerabilities"]:
            html += """
            <div class="section">
                <h2>Vulnerabilities</h2>
            """
            for vuln in self.results["vulnerabilities"]:
                html += f"""
                <div class="vulnerability">
                    <h3>{vuln['type']}</h3>
                    <p>Timestamp: {vuln['timestamp']}</p>
                    <pre>{json.dumps(vuln['details'], indent=2)}</pre>
                </div>
                """
            html += "</div>"
            
        html += """
        </body>
        </html>
        """
        return html
        
    def _generate_text(self) -> str:
        """Generate text report."""
        text = f"""
SQL Injection Scan Results
=========================

Scan Information
---------------
Target: {self.results['scan_info']['target']}
Start Time: {self.results['scan_info']['start_time']}
End Time: {self.results['scan_info']['end_time']}
Techniques: {', '.join(self.results['scan_info']['techniques'])}

Statistics
----------
Total Tests: {self.results['statistics']['total_tests']}
Successful Tests: {self.results['statistics']['successful_tests']}
Failed Tests: {self.results['statistics']['failed_tests']}
Vulnerabilities Found: {self.results['statistics']['vulnerabilities_found']}
"""
        
        if self.results["waf_info"]:
            text += f"""
WAF Information
--------------
{json.dumps(self.results['waf_info'], indent=2)}
"""
            
        if self.results["database_info"]:
            text += f"""
Database Information
------------------
{json.dumps(self.results['database_info'], indent=2)}
"""
            
        if self.results["vulnerabilities"]:
            text += """
Vulnerabilities
-------------
"""
            for vuln in self.results["vulnerabilities"]:
                text += f"""
Type: {vuln['type']}
Timestamp: {vuln['timestamp']}
Details:
{json.dumps(vuln['details'], indent=2)}
"""
                
        return text
        
    def set_format(self, format: str) -> None:
        """Set output format."""
        if format not in ["json", "html", "txt"]:
            raise ValueError(f"Unsupported output format: {format}")
        self.format = format
        
    def set_output_file(self, output_file: str) -> None:
        """Set output file path."""
        self.output_file = output_file 
