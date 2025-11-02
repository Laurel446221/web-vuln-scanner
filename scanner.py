import socket
import requests
from bs4 import BeautifulSoup
import re
import threading
from urllib.parse import urljoin, urlparse

class WebVulnerabilityScanner:
    def __init__(self, target, ports=[80, 443, 8080, 21, 22], timeout=5):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.results = {
            'open_ports': {},
            'technologies': [],
            'emails': [],
            'vulnerable_paths': [],
            'security_issues': [],
            'recommendations': []
        }
    
    def run_comprehensive_scan(self):
        print(f"[*] Starting comprehensive scan for: {self.target}")
        print("[*] Developed by Laurel Megida")
        
        self.port_scanning()
        self.technology_detection()
        self.email_discovery()
        self.path_discovery()
        self.security_analysis()
        self.generate_report()
    
    def port_scanning(self):
        print("\n[🔍] PHASE 1: PORT & SERVICE DISCOVERY")
        for port in self.ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.target, port))
                
                if result == 0:
                    # Try to get banner
                    try:
                        sock.settimeout(3)
                        banner = sock.recv(1024).decode().strip()
                        if banner:
                            service_info = f"{banner[:50]}..."
                        else:
                            service_info = "Service detected"
                    except:
                        service_info = "Service detected"
                    
                    self.results['open_ports'][port] = service_info
                    print(f"    ✅ Port {port}/open: {service_info}")
                sock.close()
            except Exception as e:
                print(f"    ❌ Port {port} scan error: {e}")
    
    def technology_detection(self):
        print("\n[🛠️] PHASE 2: TECHNOLOGY DETECTION")
        try:
            # Try both HTTP and HTTPS
            protocols = ['http', 'https']
            success = False
            
            for protocol in protocols:
                try:
                    url = f"{protocol}://{self.target}"
                    response = requests.get(url, timeout=10, headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    }, verify=False)
                    
                    success = True
                    
                    # Detect server technology
                    server = response.headers.get('Server', 'Unknown')
                    if server != 'Unknown':
                        self.results['technologies'].append(f"Web Server: {server}")
                        print(f"    ✅ Web Server: {server}")
                    
                    # Detect PHP
                    powered_by = response.headers.get('X-Powered-By', '')
                    if 'php' in response.text.lower() or 'PHP' in powered_by:
                        self.results['technologies'].append("PHP detected")
                        print("    ✅ PHP detected")
                    
                    # Detect WordPress
                    if 'wp-content' in response.text or 'wordpress' in response.text.lower():
                        self.results['technologies'].append("WordPress CMS")
                        print("    ✅ WordPress CMS")
                    
                    # Detect JavaScript frameworks
                    if 'react' in response.text.lower() or 'vue' in response.text.lower():
                        self.results['technologies'].append("JavaScript Framework")
                        print("    ✅ JavaScript Framework")
                    
                    # Detect Apache
                    if 'apache' in server.lower():
                        self.results['technologies'].append("Apache Web Server")
                        print("    ✅ Apache Web Server")
                    
                    # Detect Nginx
                    if 'nginx' in server.lower():
                        self.results['technologies'].append("Nginx Web Server")
                        print("    ✅ Nginx Web Server")
                        
                    break  # Stop if one protocol works
                    
                except requests.exceptions.SSLError:
                    continue  # Try next protocol
                except Exception as e:
                    continue  # Try next protocol
                    
            if not success:
                print("    ❌ Technology detection failed: Could not connect to target")
                
        except Exception as e:
            print(f"    ❌ Technology detection failed: {e}")
    
    def email_discovery(self):  # Fixed indentation
        print("\n[📧] PHASE 3: EMAIL DISCOVERY")
        try:
            # Try both HTTP and HTTPS
            protocols = ['http', 'https']
            emails_found = False
            
            for protocol in protocols:
                try:
                    url = f"{protocol}://{self.target}"
                    response = requests.get(url, timeout=10, headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    }, verify=False)
                    
                    # Find emails in page content
                    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', response.text)
                    unique_emails = set(emails)
                    
                    for email in unique_emails:
                        self.results['emails'].append(email)
                        print(f"    📧 {email}")
                    
                    if unique_emails:
                        emails_found = True
                        break  # Stop if we found emails
                        
                except:
                    continue
            
            if not emails_found:
                print("    ℹ️  No emails found")
                
        except Exception as e:
            print(f"    ❌ Email discovery failed: {e}")

    def path_discovery(self):
        print("\n[📁] PHASE 4: PATH DISCOVERY")
        common_paths = [
            'admin', 'login', 'wp-admin', 'phpmyadmin', 
            'config.php', 'backup', 'robots.txt', 
            '.git', '.env', 'backup.zip', 'test.php',
            'admin.php', 'debug.php', 'phpinfo.php'
        ]
        
        found_paths = 0
        protocols = ['http', 'https']
        
        for protocol in protocols:
            for path in common_paths:
                try:
                    url = f"{protocol}://{self.target}/{path}"
                    response = requests.get(url, timeout=5, headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    }, verify=False, allow_redirects=False)
                    
                    if response.status_code in [200, 301, 302, 403]:
                        status_text = {
                            200: "200 OK",
                            301: "301 Redirect", 
                            302: "302 Redirect",
                            403: "403 Forbidden"
                        }.get(response.status_code, str(response.status_code))
                        
                        self.results['vulnerable_paths'].append(f"{path} - {status_text}")
                        print(f"    🔍 Found: /{path} - {status_text}")
                        found_paths += 1
                        
                        # Add security issues for sensitive paths
                        if path in ['config.php', '.env', '.git', 'phpinfo.php']:
                            self.results['security_issues'].append(f"Sensitive file exposed: /{path}")
                            
                except requests.exceptions.RequestException:
                    continue
                except Exception as e:
                    continue
        
        if found_paths == 0:
            print("    ℹ️  No common paths found")

    def security_analysis(self):
        print("\n[🛡️] PHASE 5: SECURITY ANALYSIS")
        
        # Analyze results for security issues
        if len(self.results['open_ports']) > 5:
            self.results['security_issues'].append("Multiple ports open - reduce attack surface")
            
        if any('php' in tech.lower() for tech in self.results['technologies']):
            self.results['security_issues'].append("PHP detected - ensure latest security patches")
            
        if any('config' in path for path in self.results['vulnerable_paths']):
            self.results['security_issues'].append("Configuration files accessible - restrict access")
            
        if any('.env' in path for path in self.results['vulnerable_paths']):
            self.results['security_issues'].append("Environment file exposed - contains sensitive data")
            
        if any('.git' in path for path in self.results['vulnerable_paths']):
            self.results['security_issues'].append("Git repository exposed - source code leakage risk")
        
        # Generate recommendations
        self.generate_recommendations()
        
        # Display findings
        if self.results['security_issues']:
            for issue in self.results['security_issues']:
                print(f"    ⚠️  {issue}")
        else:
            print("    ✅ No critical security issues detected")
            
        if self.results['recommendations']:
            for recommendation in self.results['recommendations']:
                print(f"    💡 {recommendation}")

    def generate_recommendations(self):
        """Generate security recommendations based on findings"""
        
        # Port security
        if 22 in self.results['open_ports']:
            self.results['recommendations'].append("SSH port open - use key-based authentication")
            
        if 21 in self.results['open_ports']:
            self.results['recommendations'].append("FTP port open - consider using SFTP instead")
            
        if 23 in self.results['open_ports']:
            self.results['recommendations'].append("Telnet port open - insecure, disable immediately")
            
        # Web security
        if any('nginx' in tech.lower() for tech in self.results['technologies']):
            self.results['recommendations'].append("Update nginx to latest version for security patches")
            
        if any('apache' in tech.lower() for tech in self.results['technologies']):
            self.results['recommendations'].append("Update Apache to latest version for security patches")
            
        if any('wordpress' in tech.lower() for tech in self.results['technologies']):
            self.results['recommendations'].append("Keep WordPress and plugins updated regularly")
            
        # General recommendations
        self.results['recommendations'].append("Implement Web Application Firewall (WAF)")
        self.results['recommendations'].append("Regular security scanning and penetration testing")
        self.results['recommendations'].append("Use HTTPS with proper SSL/TLS configuration")
        self.results['recommendations'].append("Implement proper access controls for sensitive paths")

    def generate_report(self):
        print("\n" + "="*60)
        print("📊 COMPREHENSIVE SECURITY REPORT")
        print("="*60)
        print(f"Target: {self.target}")
        print(f"Scanner: WebVulnScanner by Laurel Megida")
        
        print(f"\n🎯 SCAN SUMMARY:")
        print(f"   • Open Ports: {len(self.results['open_ports'])}")
        print(f"   • Technologies: {len(self.results['technologies'])}")
        print(f"   • Emails Found: {len(self.results['emails'])}")
        print(f"   • Vulnerable Paths: {len(self.results['vulnerable_paths'])}")
        print(f"   • Security Issues: {len(self.results['security_issues'])}")
        
        # Display open ports
        if self.results['open_ports']:
            print(f"\n🔓 OPEN PORTS:")
            for port, service in self.results['open_ports'].items():
                print(f"   • Port {port}: {service}")
        
        # Display technologies
        if self.results['technologies']:
            print(f"\n🛠️ TECHNOLOGIES DETECTED:")
            for tech in self.results['technologies']:
                print(f"   • {tech}")
        
        # Display emails
        if self.results['emails']:
            print(f"\n📧 EMAILS DISCOVERED:")
            for email in self.results['emails']:
                print(f"   • {email}")
        
        # Display vulnerable paths
        if self.results['vulnerable_paths']:
            print(f"\n📁 ACCESSIBLE PATHS:")
            for path in self.results['vulnerable_paths']:
                print(f"   • {path}")
        
        if self.results['security_issues']:
            print(f"\n🚨 CRITICAL FINDINGS:")
            for issue in self.results['security_issues']:
                print(f"   • {issue}")
                
        if self.results['recommendations']:
            print(f"\n💡 SECURITY RECOMMENDATIONS:")
            for rec in self.results['recommendations']:
                print(f"   • {rec}")
                
        print(f"\n🛡️  Overall Security Score: {self.calculate_security_score()}/100")
        print("\nDeveloped by Laurel Megida - Professional Security Tool")

    def calculate_security_score(self):
        """Calculate a simple security score (0-100)"""
        score = 100
        
        # Deduct points for issues
        score -= len(self.results['open_ports']) * 5
        score -= len(self.results['security_issues']) * 10
        score -= len(self.results['vulnerable_paths']) * 3
        
        # Bonus for good practices
        if any('https' in tech.lower() for tech in self.results['technologies']):
            score += 10
            
        return max(0, min(100, score))

# Test the scanner
if __name__ == "__main__":
    scanner = WebVulnerabilityScanner("example.com")
    scanner.run_comprehensive_scan()