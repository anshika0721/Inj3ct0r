import json
import os
from typing import Any, Dict, Optional

class ConfigManager:
    def __init__(self, config_file: str = "config.json"):
        """Initialize configuration manager."""
        self.config_file = config_file
        self.config = self._load_config()
        
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return self._get_default_config()
        return self._get_default_config()
        
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "request": {
                "timeout": 30,
                "verify_ssl": True,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "headers": {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "close"
                }
            },
            "injection": {
                "techniques": ["error", "union", "blind", "time", "stacked"],
                "max_columns": 10,
                "delay": 5,
                "timeout": 30,
                "threads": 10
            },
            "waf": {
                "detection": True,
                "bypass": True,
                "techniques": ["encoding", "comments", "concatenation", "whitespace", "case"]
            },
            "database": {
                "types": ["mysql", "postgresql", "mssql", "sqlite"],
                "default_port": {
                    "mysql": 3306,
                    "postgresql": 5432,
                    "mssql": 1433,
                    "sqlite": None
                }
            },
            "logging": {
                "level": "INFO",
                "file": "logs/sql_injector.log",
                "max_size": 10485760,  # 10MB
                "backup_count": 5
            },
            "output": {
                "format": "json",
                "file": "results.json",
                "verbose": False
            }
        }
        
    def save_config(self) -> None:
        """Save configuration to file."""
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)
            
    def get_config(self) -> Dict[str, Any]:
        """Get current configuration."""
        return self.config
        
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get configuration section."""
        return self.config.get(section, {})
        
    def get_value(self, section: str, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        return self.config.get(section, {}).get(key, default)
        
    def set_value(self, section: str, key: str, value: Any) -> None:
        """Set configuration value."""
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value
        
    def update_section(self, section: str, values: Dict[str, Any]) -> None:
        """Update configuration section."""
        self.config[section] = values
        
    def reset_section(self, section: str) -> None:
        """Reset configuration section to default."""
        default_config = self._get_default_config()
        if section in default_config:
            self.config[section] = default_config[section]
            
    def reset_all(self) -> None:
        """Reset all configuration to default."""
        self.config = self._get_default_config()
        
    def validate_config(self) -> bool:
        """Validate configuration."""
        required_sections = ["request", "injection", "waf", "database", "logging", "output"]
        for section in required_sections:
            if section not in self.config:
                return False
        return True
        
    def get_request_config(self) -> Dict[str, Any]:
        """Get request configuration."""
        return self.get_section("request")
        
    def get_injection_config(self) -> Dict[str, Any]:
        """Get injection configuration."""
        return self.get_section("injection")
        
    def get_waf_config(self) -> Dict[str, Any]:
        """Get WAF configuration."""
        return self.get_section("waf")
        
    def get_database_config(self) -> Dict[str, Any]:
        """Get database configuration."""
        return self.get_section("database")
        
    def get_logging_config(self) -> Dict[str, Any]:
        """Get logging configuration."""
        return self.get_section("logging")
        
    def get_output_config(self) -> Dict[str, Any]:
        """Get output configuration."""
        return self.get_section("output")
        
    def set_request_config(self, config: Dict[str, Any]) -> None:
        """Set request configuration."""
        self.update_section("request", config)
        
    def set_injection_config(self, config: Dict[str, Any]) -> None:
        """Set injection configuration."""
        self.update_section("injection", config)
        
    def set_waf_config(self, config: Dict[str, Any]) -> None:
        """Set WAF configuration."""
        self.update_section("waf", config)
        
    def set_database_config(self, config: Dict[str, Any]) -> None:
        """Set database configuration."""
        self.update_section("database", config)
        
    def set_logging_config(self, config: Dict[str, Any]) -> None:
        """Set logging configuration."""
        self.update_section("logging", config)
        
    def set_output_config(self, config: Dict[str, Any]) -> None:
        """Set output configuration."""
        self.update_section("output", config) 
