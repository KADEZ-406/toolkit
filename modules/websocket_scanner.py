import websocket
import json
import threading
import time
from colorama import Fore, Style

class WebSocketScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.ws = None
        self.messages_received = []
        self.connection_closed = False

    def scan_websocket_security(self):
        print(f"\n{Fore.CYAN}[*] Starting WebSocket Security Scan...{Style.RESET_ALL}")
        
        try:
            # Check connection
            self._check_connection()
            
            # Check authentication
            self._check_authentication()
            
            # Check message validation
            self._check_message_validation()
            
            # Check for sensitive data
            self._check_sensitive_data()
            
            # Check for origin validation
            self._check_origin_validation()
            
            # Check for rate limiting
            self._check_rate_limiting()
            
            # Print results
            self._print_results()
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error scanning WebSocket: {str(e)}{Style.RESET_ALL}")
        finally:
            if self.ws:
                self.ws.close()

    def _on_message(self, ws, message):
        self.messages_received.append(message)

    def _on_error(self, ws, error):
        print(f"{Fore.RED}[!] WebSocket error: {str(error)}{Style.RESET_ALL}")

    def _on_close(self, ws, close_status_code, close_msg):
        self.connection_closed = True

    def _on_open(self, ws):
        pass

    def _check_connection(self):
        try:
            websocket.enableTrace(True)
            self.ws = websocket.WebSocketApp(
                self.target_url,
                on_message=self._on_message,
                on_error=self._on_error,
                on_close=self._on_close,
                on_open=self._on_open
            )
            
            # Start WebSocket connection in a separate thread
            wst = threading.Thread(target=self.ws.run_forever)
            wst.daemon = True
            wst.start()
            
            # Wait for connection
            time.sleep(2)
            
            if self.connection_closed:
                self.vulnerabilities.append({
                    'type': 'Connection Failed',
                    'severity': 'High',
                    'description': 'Could not establish WebSocket connection'
                })
        except Exception as e:
            self.vulnerabilities.append({
                'type': 'Connection Error',
                'severity': 'High',
                'description': f'Error connecting to WebSocket: {str(e)}'
            })

    def _check_authentication(self):
        if not self.ws:
            return
            
        try:
            # Test without authentication
            self.ws.send(json.dumps({"action": "test"}))
            time.sleep(1)
            
            if not self.connection_closed:
                self.vulnerabilities.append({
                    'type': 'Missing Authentication',
                    'severity': 'High',
                    'description': 'WebSocket accepts messages without authentication'
                })
        except:
            pass

    def _check_message_validation(self):
        if not self.ws:
            return
            
        test_payloads = [
            {"action": "test", "data": "<script>alert(1)</script>"},
            {"action": "test", "data": "' OR '1'='1"},
            {"action": "test", "data": "../../../etc/passwd"},
            {"action": "test", "data": "'; DROP TABLE users; --"}
        ]
        
        for payload in test_payloads:
            try:
                self.ws.send(json.dumps(payload))
                time.sleep(1)
                
                if not self.connection_closed:
                    self.vulnerabilities.append({
                        'type': 'Weak Message Validation',
                        'severity': 'High',
                        'description': f'WebSocket accepts potentially malicious payload: {payload}'
                    })
            except:
                pass

    def _check_sensitive_data(self):
        if not self.ws:
            return
            
        try:
            # Send a test message
            self.ws.send(json.dumps({"action": "test"}))
            time.sleep(1)
            
            # Check received messages for sensitive data
            for message in self.messages_received:
                message_str = str(message).lower()
                sensitive_patterns = [
                    'password',
                    'token',
                    'key',
                    'secret',
                    'credential',
                    'api_key',
                    'private',
                    'admin'
                ]
                
                for pattern in sensitive_patterns:
                    if pattern in message_str:
                        self.vulnerabilities.append({
                            'type': 'Sensitive Data Exposure',
                            'severity': 'High',
                            'description': f'WebSocket response contains potentially sensitive data: {pattern}'
                        })
        except:
            pass

    def _check_origin_validation(self):
        if not self.ws:
            return
            
        try:
            # Test with different origin
            headers = {
                'Origin': 'https://evil.com'
            }
            
            self.ws.close()
            self.ws = websocket.WebSocketApp(
                self.target_url,
                header=headers,
                on_message=self._on_message,
                on_error=self._on_error,
                on_close=self._on_close,
                on_open=self._on_open
            )
            
            wst = threading.Thread(target=self.ws.run_forever)
            wst.daemon = True
            wst.start()
            
            time.sleep(2)
            
            if not self.connection_closed:
                self.vulnerabilities.append({
                    'type': 'Missing Origin Validation',
                    'severity': 'High',
                    'description': 'WebSocket accepts connections from any origin'
                })
        except:
            pass

    def _check_rate_limiting(self):
        if not self.ws:
            return
            
        try:
            # Send multiple messages in quick succession
            for _ in range(10):
                self.ws.send(json.dumps({"action": "test"}))
                time.sleep(0.1)
            
            if not self.connection_closed:
                self.vulnerabilities.append({
                    'type': 'No Rate Limiting',
                    'severity': 'Medium',
                    'description': 'WebSocket does not implement rate limiting'
                })
        except:
            pass

    def _print_results(self):
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] No vulnerabilities found in WebSocket{Style.RESET_ALL}")
            return

        print(f"\n{Fore.YELLOW}[!] Found {len(self.vulnerabilities)} potential issues:{Style.RESET_ALL}")
        for vuln in self.vulnerabilities:
            severity_color = {
                'High': Fore.RED,
                'Medium': Fore.YELLOW,
                'Low': Fore.BLUE,
                'Info': Fore.CYAN
            }.get(vuln['severity'], Fore.WHITE)
            
            print(f"\n{severity_color}[{vuln['severity']}] {vuln['type']}{Style.RESET_ALL}")
            print(f"Description: {vuln['description']}") 