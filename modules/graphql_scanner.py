import requests
import json
from colorama import Fore, Style

class GraphQLScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.introspection_query = """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    ...FullType
                }
                directives {
                    name
                    description
                    locations
                    args {
                        ...InputValue
                    }
                }
            }
        }
        fragment FullType on __Type {
            kind
            name
            description
            fields(includeDeprecated: true) {
                name
                description
                args {
                    ...InputValue
                }
                type {
                    ...TypeRef
                }
                isDeprecated
                deprecationReason
            }
            inputFields {
                ...InputValue
            }
            interfaces {
                ...TypeRef
            }
            enumValues(includeDeprecated: true) {
                name
                description
                isDeprecated
                deprecationReason
            }
            possibleTypes {
                ...TypeRef
            }
        }
        fragment InputValue on __InputValue {
            name
            description
            type { ...TypeRef }
            defaultValue
        }
        fragment TypeRef on __Type {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                                ofType {
                                    kind
                                    name
                                    ofType {
                                        kind
                                        name
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """

    def scan_vulnerabilities(self):
        print(f"\n{Fore.CYAN}[*] Starting GraphQL Vulnerability Scan...{Style.RESET_ALL}")
        
        try:
            # Check if introspection is enabled
            self._check_introspection()
            
            # Check for batch query support
            self._check_batch_queries()
            
            # Check for field suggestions
            self._check_field_suggestions()
            
            # Check for error messages
            self._check_error_messages()
            
            # Check for query complexity
            self._check_query_complexity()
            
            # Print results
            self._print_results()
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error scanning GraphQL endpoint: {str(e)}{Style.RESET_ALL}")

    def _check_introspection(self):
        try:
            response = requests.post(
                self.target_url,
                json={'query': self.introspection_query},
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                if '__schema' in data.get('data', {}):
                    self.vulnerabilities.append({
                        'type': 'Introspection Enabled',
                        'severity': 'High',
                        'description': 'GraphQL introspection is enabled, exposing the entire API schema'
                    })
        except:
            pass

    def _check_batch_queries(self):
        try:
            batch_query = [
                {'query': '{ __typename }'},
                {'query': '{ __typename }'}
            ]
            
            response = requests.post(
                self.target_url,
                json=batch_query,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    self.vulnerabilities.append({
                        'type': 'Batch Queries Enabled',
                        'severity': 'Medium',
                        'description': 'GraphQL endpoint supports batch queries, which may lead to DoS attacks'
                    })
        except:
            pass

    def _check_field_suggestions(self):
        try:
            response = requests.post(
                self.target_url,
                json={'query': '{ __typo__ }'},
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'suggestions' in str(data):
                    self.vulnerabilities.append({
                        'type': 'Field Suggestions Enabled',
                        'severity': 'Low',
                        'description': 'GraphQL endpoint provides field suggestions, potentially leaking schema information'
                    })
        except:
            pass

    def _check_error_messages(self):
        try:
            response = requests.post(
                self.target_url,
                json={'query': '{ invalidField }'},
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'errors' in data and len(data['errors']) > 0:
                    error_msg = str(data['errors'][0])
                    if len(error_msg) > 100:  # Detailed error messages
                        self.vulnerabilities.append({
                            'type': 'Detailed Error Messages',
                            'severity': 'Medium',
                            'description': 'GraphQL endpoint returns detailed error messages, potentially leaking sensitive information'
                        })
        except:
            pass

    def _check_query_complexity(self):
        try:
            # Create a complex nested query
            complex_query = '{ __typename ' + '{ __typename ' * 10 + '}' * 10 + '}'
            
            response = requests.post(
                self.target_url,
                json={'query': complex_query},
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                self.vulnerabilities.append({
                    'type': 'No Query Complexity Limit',
                    'severity': 'High',
                    'description': 'GraphQL endpoint has no query complexity limit, potentially vulnerable to DoS attacks'
                })
        except:
            pass

    def _print_results(self):
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] No vulnerabilities found in GraphQL endpoint{Style.RESET_ALL}")
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