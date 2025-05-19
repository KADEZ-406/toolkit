import websocket
from websocket import WebSocketApp
import json
import time
from colorama import Fore, Style
import threading
import queue

class WebSocketFuzzer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.message_queue = queue.Queue()
        self.fuzzing_complete = False

    def fuzz_websocket(self):
        print(f"\n{Fore.CYAN}[*] Starting WebSocket Fuzzing...{Style.RESET_ALL}")
        
        try:
            # Connect to WebSocket
            ws = WebSocketApp(
                self.target_url,
                on_message=self._on_message,
                on_error=self._on_error,
                on_close=self._on_close,
                on_open=self._on_open
            )
            
            # Start WebSocket connection in a separate thread
            ws_thread = threading.Thread(target=ws.run_forever)
            ws_thread.daemon = True
            ws_thread.start()
            
            # Wait for connection
            time.sleep(2)
            
            # Start fuzzing
            self._fuzz_messages(ws)
            self._fuzz_headers(ws)
            self._fuzz_protocols(ws)
            self._fuzz_payloads(ws)
            
            # Wait for fuzzing to complete
            self.fuzzing_complete = True
            time.sleep(5)
            
            # Print results
            self._print_results()
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error during WebSocket fuzzing: {str(e)}{Style.RESET_ALL}")

    def _on_message(self, ws, message):
        try:
            self.message_queue.put(message)
        except:
            pass

    def _on_error(self, ws, error):
        self.vulnerabilities.append({
            'type': 'WebSocket Error',
            'severity': 'Medium',
            'description': f'Error occurred: {str(error)}'
        })

    def _on_close(self, ws, close_status_code, close_msg):
        if not self.fuzzing_complete:
            self.vulnerabilities.append({
                'type': 'Unexpected WebSocket Closure',
                'severity': 'Medium',
                'description': f'Connection closed with status {close_status_code}: {close_msg}'
            })

    def _on_open(self, ws):
        print(f"{Fore.GREEN}[+] WebSocket connection established{Style.RESET_ALL}")

    def _fuzz_messages(self, ws):
        message_payloads = [
            {"type": "ping", "data": "test"},
            {"type": "message", "data": None},
            {"type": "message", "data": ""},
            {"type": "message", "data": " "},
            {"type": "message", "data": "test"},
            {"type": "message", "data": "test" * 1000},
            {"type": "message", "data": "<script>alert(1)</script>"},
            {"type": "message", "data": {"key": "value"}},
            {"type": "message", "data": [1, 2, 3]},
            {"type": "message", "data": True}
        ]
        
        for payload in message_payloads:
            try:
                ws.send(json.dumps(payload))
                time.sleep(0.5)
                
                # Check response
                try:
                    response = self.message_queue.get(timeout=1)
                    if "error" in response.lower():
                        self.vulnerabilities.append({
                            'type': 'Message Handling Error',
                            'severity': 'Medium',
                            'description': f'Error handling message: {payload}'
                        })
                except queue.Empty:
                    pass
            except:
                pass

    def _fuzz_headers(self, ws):
        header_payloads = [
            {"Origin": "https://evil.com"},
            {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            {"Cookie": "session=test"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"}
        ]
        
        for headers in header_payloads:
            try:
                ws.close()
                ws = WebSocketApp(
                    self.target_url,
                    header=headers,
                    on_message=self._on_message,
                    on_error=self._on_error,
                    on_close=self._on_close,
                    on_open=self._on_open
                )
                ws.run_forever()
                time.sleep(1)
            except:
                pass

    def _fuzz_protocols(self, ws):
        protocols = [
            ["wss"],
            ["ws"],
            ["wss", "ws"],
            ["http"],
            ["https"],
            ["ftp"]
        ]
        
        for protocol in protocols:
            try:
                ws.close()
                ws = WebSocketApp(
                    self.target_url,
                    subprotocols=protocol,
                    on_message=self._on_message,
                    on_error=self._on_error,
                    on_close=self._on_close,
                    on_open=self._on_open
                )
                ws.run_forever()
                time.sleep(1)
            except:
                pass

    def _fuzz_payloads(self, ws):
        payloads = [
            "null",
            "undefined",
            "NaN",
            "Infinity",
            "-Infinity",
            "true",
            "false",
            "{}",
            "[]",
            "''",
            '""',
            "0",
            "-0",
            "0.0",
            "-0.0",
            "1",
            "-1",
            "1.0",
            "-1.0"
        ]
        
        for payload in payloads:
            try:
                ws.send(payload)
                time.sleep(0.5)
                
                # Check response
                try:
                    response = self.message_queue.get(timeout=1)
                    if "error" in response.lower():
                        self.vulnerabilities.append({
                            'type': 'Payload Handling Error',
                            'severity': 'Medium',
                            'description': f'Error handling payload: {payload}'
                        })
                except queue.Empty:
                    pass
            except:
                pass

    def _print_results(self):
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] No WebSocket vulnerabilities found{Style.RESET_ALL}")
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