import requests
import json
from colorama import Fore, Style
import re

class GraphQLSchemaAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.common_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Content-Type': 'application/json',
            'Accept': '*/*'
        }

    def analyze_schema(self):
        print(f"\n{Fore.CYAN}[*] Starting GraphQL Schema Analysis...{Style.RESET_ALL}")
        
        try:
            # Get schema through introspection
            schema = self._get_schema()
            if not schema:
                return
            
            # Analyze schema
            self._analyze_queries(schema)
            self._analyze_mutations(schema)
            self._analyze_subscriptions(schema)
            self._analyze_types(schema)
            self._analyze_directives(schema)
            self._analyze_deprecations(schema)
            
            # Print results
            self._print_results()
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error analyzing GraphQL schema: {str(e)}{Style.RESET_ALL}")

    def _get_schema(self):
        introspection_query = {
            "query": """
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
        }
        
        try:
            response = requests.post(
                self.target_url,
                headers=self.common_headers,
                json=introspection_query
            )
            
            if response.status_code == 200:
                return response.json().get('data', {}).get('__schema')
            else:
                self.vulnerabilities.append({
                    'type': 'Introspection Disabled',
                    'severity': 'Info',
                    'description': 'GraphQL introspection is disabled'
                })
                return None
                
        except:
            self.vulnerabilities.append({
                'type': 'Schema Access Error',
                'severity': 'High',
                'description': 'Could not access GraphQL schema'
            })
            return None

    def _analyze_queries(self, schema):
        query_type = next((t for t in schema['types'] if t['name'] == schema['queryType']['name']), None)
        if not query_type:
            return
            
        for field in query_type.get('fields', []):
            # Check for sensitive data exposure
            if any(sensitive in field['name'].lower() for sensitive in ['password', 'secret', 'key', 'token', 'auth']):
                self.vulnerabilities.append({
                    'type': 'Sensitive Data Exposure',
                    'severity': 'High',
                    'description': f'Query {field["name"]} may expose sensitive data'
                })
            
            # Check for missing authentication
            if not any(arg['name'] == 'token' or arg['name'] == 'auth' for arg in field.get('args', [])):
                self.vulnerabilities.append({
                    'type': 'Missing Authentication',
                    'severity': 'High',
                    'description': f'Query {field["name"]} has no authentication parameter'
                })

    def _analyze_mutations(self, schema):
        mutation_type = next((t for t in schema['types'] if t['name'] == schema['mutationType']['name']), None)
        if not mutation_type:
            return
            
        for field in mutation_type.get('fields', []):
            # Check for missing input validation
            if not field.get('args'):
                self.vulnerabilities.append({
                    'type': 'Missing Input Validation',
                    'severity': 'High',
                    'description': f'Mutation {field["name"]} has no input validation'
                })
            
            # Check for missing authentication
            if not any(arg['name'] == 'token' or arg['name'] == 'auth' for arg in field.get('args', [])):
                self.vulnerabilities.append({
                    'type': 'Missing Authentication',
                    'severity': 'High',
                    'description': f'Mutation {field["name"]} has no authentication parameter'
                })

    def _analyze_subscriptions(self, schema):
        subscription_type = next((t for t in schema['types'] if t['name'] == schema['subscriptionType']['name']), None)
        if not subscription_type:
            return
            
        for field in subscription_type.get('fields', []):
            # Check for missing authentication
            if not any(arg['name'] == 'token' or arg['name'] == 'auth' for arg in field.get('args', [])):
                self.vulnerabilities.append({
                    'type': 'Missing Authentication',
                    'severity': 'High',
                    'description': f'Subscription {field["name"]} has no authentication parameter'
                })

    def _analyze_types(self, schema):
        for type_def in schema['types']:
            # Check for sensitive type names
            if any(sensitive in type_def['name'].lower() for sensitive in ['password', 'secret', 'key', 'token', 'auth']):
                self.vulnerabilities.append({
                    'type': 'Sensitive Type Name',
                    'severity': 'Medium',
                    'description': f'Type {type_def["name"]} may contain sensitive data'
                })
            
            # Check for missing descriptions
            if not type_def.get('description'):
                self.vulnerabilities.append({
                    'type': 'Missing Type Description',
                    'severity': 'Low',
                    'description': f'Type {type_def["name"]} has no description'
                })

    def _analyze_directives(self, schema):
        for directive in schema['directives']:
            # Check for missing descriptions
            if not directive.get('description'):
                self.vulnerabilities.append({
                    'type': 'Missing Directive Description',
                    'severity': 'Low',
                    'description': f'Directive {directive["name"]} has no description'
                })
            
            # Check for missing arguments
            if not directive.get('args'):
                self.vulnerabilities.append({
                    'type': 'Missing Directive Arguments',
                    'severity': 'Low',
                    'description': f'Directive {directive["name"]} has no arguments'
                })

    def _analyze_deprecations(self, schema):
        for type_def in schema['types']:
            for field in type_def.get('fields', []):
                if field.get('isDeprecated'):
                    self.vulnerabilities.append({
                        'type': 'Deprecated Field',
                        'severity': 'Info',
                        'description': f'Field {field["name"]} in type {type_def["name"]} is deprecated: {field.get("deprecationReason", "No reason provided")}'
                    })

    def _print_results(self):
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] No GraphQL schema vulnerabilities found{Style.RESET_ALL}")
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