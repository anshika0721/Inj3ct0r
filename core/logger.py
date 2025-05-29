import logging
import os
from datetime import datetime
from typing import Optional
from colorama import Fore, Style, init

class Logger:
    def __init__(self, log_file: Optional[str] = None, log_level: int = logging.INFO):
        """Initialize logger with file and console handlers."""
        # Initialize colorama
        init()
        
        # Create logger
        self.logger = logging.getLogger("SQLInjector")
        self.logger.setLevel(log_level)
        
        # Create formatters
        file_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        
        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # Create file handler if log file is specified
        if log_file:
            # Create logs directory if it doesn't exist
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
                
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
            
    def info(self, message: str) -> None:
        """Log info message."""
        self.logger.info(f"{Fore.GREEN}{message}{Style.RESET_ALL}")
        
    def warning(self, message: str) -> None:
        """Log warning message."""
        self.logger.warning(f"{Fore.YELLOW}{message}{Style.RESET_ALL}")
        
    def error(self, message: str) -> None:
        """Log error message."""
        self.logger.error(f"{Fore.RED}{message}{Style.RESET_ALL}")
        
    def debug(self, message: str) -> None:
        """Log debug message."""
        self.logger.debug(f"{Fore.BLUE}{message}{Style.RESET_ALL}")
        
    def critical(self, message: str) -> None:
        """Log critical message."""
        self.logger.critical(f"{Fore.RED}{Style.BRIGHT}{message}{Style.RESET_ALL}")
        
    def success(self, message: str) -> None:
        """Log success message."""
        self.logger.info(f"{Fore.GREEN}{Style.BRIGHT}{message}{Style.RESET_ALL}")
        
    def failure(self, message: str) -> None:
        """Log failure message."""
        self.logger.error(f"{Fore.RED}{Style.BRIGHT}{message}{Style.RESET_ALL}")
        
    def test_start(self, test_name: str) -> None:
        """Log test start message."""
        self.logger.info(f"{Fore.CYAN}Starting test: {test_name}{Style.RESET_ALL}")
        
    def test_end(self, test_name: str, success: bool) -> None:
        """Log test end message."""
        if success:
            self.logger.info(f"{Fore.GREEN}Test completed: {test_name}{Style.RESET_ALL}")
        else:
            self.logger.error(f"{Fore.RED}Test failed: {test_name}{Style.RESET_ALL}")
            
    def payload_test(self, payload: str, success: bool) -> None:
        """Log payload test result."""
        if success:
            self.logger.info(f"{Fore.GREEN}Payload successful: {payload}{Style.RESET_ALL}")
        else:
            self.logger.debug(f"{Fore.YELLOW}Payload failed: {payload}{Style.RESET_ALL}")
            
    def vulnerability_found(self, vuln_type: str, details: str) -> None:
        """Log vulnerability found message."""
        self.logger.warning(
            f"{Fore.RED}Vulnerability found - Type: {vuln_type}\n"
            f"Details: {details}{Style.RESET_ALL}"
        )
        
    def waf_detected(self, waf_type: str, confidence: float) -> None:
        """Log WAF detection message."""
        self.logger.warning(
            f"{Fore.YELLOW}WAF detected - Type: {waf_type}\n"
            f"Confidence: {confidence}%{Style.RESET_ALL}"
        )
        
    def bypass_success(self, technique: str, payload: str) -> None:
        """Log WAF bypass success message."""
        self.logger.info(
            f"{Fore.GREEN}WAF bypass successful - Technique: {technique}\n"
            f"Payload: {payload}{Style.RESET_ALL}"
        )
        
    def scan_progress(self, current: int, total: int, message: str) -> None:
        """Log scan progress message."""
        progress = (current / total) * 100
        self.logger.info(
            f"{Fore.CYAN}Progress: {progress:.1f}% ({current}/{total})\n"
            f"Status: {message}{Style.RESET_ALL}"
        )
        
    def scan_complete(self, results: dict) -> None:
        """Log scan completion message."""
        self.logger.info(
            f"{Fore.GREEN}Scan completed\n"
            f"Results: {results}{Style.RESET_ALL}"
        )
        
    def export_results(self, file_path: str) -> None:
        """Log results export message."""
        self.logger.info(
            f"{Fore.GREEN}Results exported to: {file_path}{Style.RESET_ALL}"
        )
        
    def set_level(self, level: int) -> None:
        """Set logging level."""
        self.logger.setLevel(level)
        
    def get_logger(self) -> logging.Logger:
        """Get the logger instance."""
        return self.logger 
