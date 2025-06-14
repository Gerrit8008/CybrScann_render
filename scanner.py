import socket
import ssl
import requests
import dns.resolver
from datetime import datetime, timezone
import concurrent.futures
from urllib.parse import urlparse
import json
import re
from typing import Dict, List, Any, Optional
import subprocess
import time
from bs4 import BeautifulSoup
import base64

class SecurityScanner:
    def __init__(self, timeout=30):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CybrScan Security Scanner/1.0'
        })
        
    def scan_domain(self, domain: str, scan_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """Perform comprehensive security scan on a domain"""
        
        # Clean domain
        domain = self._clean_domain(domain)
        
        # Default scan types
        if not scan_types:
            scan_types = ['ssl', 'ports', 'dns', 'headers', 'vulnerabilities', 
                         'subdomains', 'email_security', 'waf', 'technology', 
                         'api_security', 'cloud_misconfig', 'compliance', 'performance']
        
        results = {
            'domain': domain,
            'scan_timestamp': datetime.utcnow().isoformat(),
            'scan_types': scan_types,
            'results': {},
            'risk_score': 100,
            'vulnerabilities': [],
            'ip_info': self._get_ip_info(domain)
        }
        
        # Run scans sequentially to prevent hanging threads - DIRECT FIX
        scan_functions = {}
        if 'ssl' in scan_types:
            scan_functions['ssl'] = self.scan_ssl
        if 'ports' in scan_types:
            scan_functions['ports'] = self.scan_ports
        if 'dns' in scan_types:
            scan_functions['dns'] = self.scan_dns
        if 'headers' in scan_types:
            scan_functions['headers'] = self.scan_headers
        if 'vulnerabilities' in scan_types:
            scan_functions['vulnerabilities'] = self.scan_vulnerabilities
        if 'subdomains' in scan_types:
            scan_functions['subdomains'] = self.scan_subdomains
        if 'email_security' in scan_types:
            scan_functions['email_security'] = self.scan_email_security
        if 'waf' in scan_types:
            scan_functions['waf'] = self.scan_waf
        if 'technology' in scan_types:
            scan_functions['technology'] = self.scan_technology
        if 'api_security' in scan_types:
            scan_functions['api_security'] = self.scan_api_security
        if 'cloud_misconfig' in scan_types:
            scan_functions['cloud_misconfig'] = self.scan_cloud_misconfig
        if 'compliance' in scan_types:
            scan_functions['compliance'] = self.scan_compliance
        if 'performance' in scan_types:
            scan_functions['performance'] = self.scan_performance
        
        # Execute scans sequentially with timeout protection
        for scan_type, scan_function in scan_functions.items():
            try:
                import signal
                
                def timeout_handler(signum, frame):
                    raise TimeoutError(f"Scan {scan_type} timed out")
                
                # Set alarm for each individual scan
                signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(10)  # 10 second timeout per scan
                
                results['results'][scan_type] = scan_function(domain)
                signal.alarm(0)  # Clear alarm
                
            except Exception as e:
                signal.alarm(0)  # Clear alarm
                results['results'][scan_type] = {
                    'error': str(e),
                    'status': 'failed'
                }
        
        # Calculate risk score
        results['risk_score'], results['vulnerabilities'] = self._calculate_risk_score(results['results'], results.get('ip_info'))
        
        return results
    
    def scan_ssl(self, domain: str) -> Dict[str, Any]:
        """Scan SSL/TLS certificate"""
        results = {
            'status': 'completed',
            'valid': False,
            'issues': [],
            'certificate': {}
        }
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Certificate details
                    results['certificate'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert.get('version'),
                        'serialNumber': cert.get('serialNumber'),
                        'notBefore': cert.get('notBefore'),
                        'notAfter': cert.get('notAfter'),
                        'subjectAltName': [x[1] for x in cert.get('subjectAltName', [])],
                        'protocol': ssock.version(),
                        'cipher': ssock.cipher()
                    }
                    
                    # Check validity
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    now = datetime.now()
                    
                    if now < not_before:
                        results['issues'].append('Certificate not yet valid')
                    elif now > not_after:
                        results['issues'].append('Certificate expired')
                        results['expired'] = True
                    else:
                        results['valid'] = True
                    
                    # Check domain match
                    cert_domains = [results['certificate']['subject'].get('commonName', '')]
                    cert_domains.extend(results['certificate'].get('subjectAltName', []))
                    
                    if not any(self._match_domain(domain, cert_domain) for cert_domain in cert_domains):
                        results['issues'].append('Certificate domain mismatch')
                        results['valid'] = False
                    
                    # Check protocol version
                    if results['certificate']['protocol'] in ['TLSv1', 'TLSv1.1']:
                        results['issues'].append(f"Outdated TLS version: {results['certificate']['protocol']}")
                    
        except socket.timeout:
            results['status'] = 'timeout'
            results['issues'].append('Connection timeout')
        except ssl.SSLError as e:
            results['status'] = 'ssl_error'
            results['issues'].append(f'SSL Error: {str(e)}')
        except Exception as e:
            results['status'] = 'error'
            results['issues'].append(f'Error: {str(e)}')
        
        return results
    
    def scan_ports(self, domain: str) -> Dict[str, Any]:
        """Scan common ports"""
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt'
        }
        
        results = {
            'status': 'completed',
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'services': {}
        }
        
        try:
            # Resolve domain to IP
            ip = socket.gethostbyname(domain)
            
            for port, service in common_ports.items():
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                
                try:
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        results['open_ports'].append(port)
                        results['services'][port] = service
                        
                        # Try to grab banner
                        try:
                            if port not in [80, 443]:  # Skip HTTP/HTTPS
                                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                                if banner:
                                    results['services'][port] = f"{service} - {banner[:100]}"
                        except:
                            pass
                    else:
                        results['closed_ports'].append(port)
                except socket.timeout:
                    results['filtered_ports'].append(port)
                except Exception:
                    results['filtered_ports'].append(port)
                finally:
                    sock.close()
        
        except socket.gaierror:
            results['status'] = 'dns_error'
            results['error'] = 'Could not resolve domain'
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def scan_dns(self, domain: str) -> Dict[str, Any]:
        """Scan DNS records"""
        results = {
            'status': 'completed',
            'records': {},
            'issues': []
        }
        
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME']
        
        for record_type in record_types:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 5
                
                answers = resolver.resolve(domain, record_type)
                results['records'][record_type] = []
                
                for rdata in answers:
                    if record_type == 'MX':
                        results['records'][record_type].append({
                            'priority': rdata.preference,
                            'exchange': str(rdata.exchange)
                        })
                    else:
                        results['records'][record_type].append(str(rdata))
                
            except dns.resolver.NXDOMAIN:
                results['issues'].append(f'Domain {domain} does not exist')
                results['status'] = 'nxdomain'
                break
            except dns.resolver.NoAnswer:
                continue
            except Exception as e:
                results['issues'].append(f'{record_type} lookup failed: {str(e)}')
        
        # Check for common security records
        security_records = {
            'SPF': None,
            'DMARC': None,
            'DKIM': None
        }
        
        # Check SPF
        txt_records = results['records'].get('TXT', [])
        for record in txt_records:
            if record.startswith('v=spf1'):
                security_records['SPF'] = record
        
        # Check DMARC
        try:
            dmarc_domain = f'_dmarc.{domain}'
            answers = resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                record = str(rdata).strip('"')
                if record.startswith('v=DMARC1'):
                    security_records['DMARC'] = record
        except:
            pass
        
        # Check DKIM (common selectors)
        dkim_selectors = ['default', 'google', 'k1', 'k2', 'selector1', 'selector2', 'mail', 'email']
        dkim_found = []
        for selector in dkim_selectors:
            try:
                dkim_domain = f'{selector}._domainkey.{domain}'
                answers = resolver.resolve(dkim_domain, 'TXT')
                for rdata in answers:
                    record = str(rdata).strip('"')
                    if 'p=' in record:  # DKIM public key
                        dkim_found.append({
                            'selector': selector,
                            'record': record[:100] + '...' if len(record) > 100 else record
                        })
            except:
                continue
        
        if dkim_found:
            security_records['DKIM'] = dkim_found
        
        results['security_records'] = security_records
        
        # Add issues for missing security records
        if not security_records['SPF']:
            results['issues'].append('No SPF record found')
        if not security_records['DMARC']:
            results['issues'].append('No DMARC record found')
        
        return results
    
    def scan_headers(self, domain: str) -> Dict[str, Any]:
        """Scan HTTP security headers"""
        results = {
            'status': 'completed',
            'headers': {},
            'missing': [],
            'issues': []
        }
        
        security_headers = {
            'Strict-Transport-Security': 'HSTS not implemented',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options',
            'X-Frame-Options': 'Clickjacking protection not implemented',
            'X-XSS-Protection': 'XSS protection header missing',
            'Content-Security-Policy': 'No Content Security Policy',
            'Referrer-Policy': 'No referrer policy set',
            'Permissions-Policy': 'No permissions policy set'
        }
        
        try:
            # Try HTTPS first
            url = f'https://{domain}'
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            
            results['headers'] = dict(response.headers)
            
            # Check security headers
            for header, issue in security_headers.items():
                if header not in response.headers:
                    results['missing'].append(header)
                    results['issues'].append(issue)
                else:
                    # Validate header values
                    value = response.headers[header]
                    if header == 'Strict-Transport-Security':
                        if 'max-age' not in value:
                            results['issues'].append('HSTS max-age not set')
                        else:
                            max_age = re.search(r'max-age=(\d+)', value)
                            if max_age and int(max_age.group(1)) < 31536000:
                                results['issues'].append('HSTS max-age less than 1 year')
            
            # Check for insecure headers
            if 'Server' in response.headers:
                results['issues'].append(f"Server header exposes version: {response.headers['Server']}")
            
            if 'X-Powered-By' in response.headers:
                results['issues'].append(f"X-Powered-By header exposes technology: {response.headers['X-Powered-By']}")
            
        except requests.exceptions.SSLError:
            # Try HTTP if HTTPS fails
            try:
                url = f'http://{domain}'
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                results['headers'] = dict(response.headers)
                results['issues'].append('Site not available over HTTPS')
            except Exception as e:
                results['status'] = 'error'
                results['error'] = str(e)
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def scan_vulnerabilities(self, domain: str) -> Dict[str, Any]:
        """Scan for common vulnerabilities"""
        results = {
            'status': 'completed',
            'vulnerabilities': [],
            'checks_performed': []
        }
        
        # Check for common vulnerable paths
        vulnerable_paths = [
            '/.git/config',
            '/.env',
            '/.htaccess',
            '/wp-config.php',
            '/config.php',
            '/phpinfo.php',
            '/.DS_Store',
            '/robots.txt',
            '/sitemap.xml',
            '/.well-known/security.txt'
        ]
        
        base_url = f'https://{domain}'
        
        for path in vulnerable_paths:
            results['checks_performed'].append(f'Path check: {path}')
            try:
                response = self.session.get(f'{base_url}{path}', timeout=5, allow_redirects=False)
                if response.status_code == 200:
                    if path in ['/.git/config', '/.env', '/wp-config.php', '/config.php']:
                        results['vulnerabilities'].append({
                            'type': 'exposed_file',
                            'severity': 'high',
                            'path': path,
                            'description': f'Sensitive file exposed: {path}'
                        })
                    elif path == '/phpinfo.php' and 'phpinfo()' in response.text:
                        results['vulnerabilities'].append({
                            'type': 'information_disclosure',
                            'severity': 'medium',
                            'path': path,
                            'description': 'PHP info page exposed'
                        })
            except:
                continue
        
        # Check for open redirects
        results['checks_performed'].append('Open redirect check')
        redirect_payloads = [
            '//evil.com',
            'https://evil.com',
            '//google.com'
        ]
        
        for payload in redirect_payloads:
            try:
                response = self.session.get(
                    f'{base_url}?url={payload}',
                    timeout=5,
                    allow_redirects=False
                )
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if payload in location or 'evil.com' in location:
                        results['vulnerabilities'].append({
                            'type': 'open_redirect',
                            'severity': 'medium',
                            'description': 'Possible open redirect vulnerability'
                        })
                        break
            except:
                continue
        
        # Check CORS misconfiguration
        results['checks_performed'].append('CORS misconfiguration check')
        try:
            headers = {'Origin': 'https://evil.com'}
            response = self.session.get(base_url, headers=headers, timeout=5)
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            if acao == '*' or acao == 'https://evil.com':
                results['vulnerabilities'].append({
                    'type': 'cors_misconfiguration',
                    'severity': 'medium',
                    'description': f'CORS misconfiguration: Access-Control-Allow-Origin set to {acao}'
                })
        except:
            pass
        
        return results
    
    def _clean_domain(self, domain: str) -> str:
        """Clean and validate domain"""
        # Remove protocol
        domain = re.sub(r'^https?://', '', domain)
        # Remove path
        domain = domain.split('/')[0]
        # Remove port
        domain = domain.split(':')[0]
        # Remove whitespace
        domain = domain.strip()
        
        return domain
    
    def _match_domain(self, domain: str, cert_domain: str) -> bool:
        """Check if domain matches certificate domain (including wildcards)"""
        if cert_domain.startswith('*.'):
            # Wildcard cert
            cert_base = cert_domain[2:]
            return domain.endswith(cert_base) and '.' in domain.replace(cert_base, '')
        return domain == cert_domain
    
    def _calculate_risk_score(self, scan_results: Dict[str, Any], ip_info: Dict[str, Any] = None) -> tuple:
        """Calculate overall risk score and compile vulnerabilities"""
        score = 100
        vulnerabilities = []
        
        # SSL scoring
        if 'ssl' in scan_results and scan_results['ssl'].get('status') == 'completed':
            ssl_results = scan_results['ssl']
            if not ssl_results.get('valid', False):
                score -= 20
                vulnerabilities.append({
                    'type': 'ssl',
                    'severity': 'high',
                    'description': 'Invalid SSL certificate'
                })
            
            for issue in ssl_results.get('issues', []):
                score -= 5
                vulnerabilities.append({
                    'type': 'ssl',
                    'severity': 'medium',
                    'description': issue
                })
        
        # Port scoring
        if 'ports' in scan_results and scan_results['ports'].get('status') == 'completed':
            risky_ports = {
                21: ('FTP', 'high'),
                23: ('Telnet', 'critical'),
                135: ('RPC', 'high'),
                139: ('NetBIOS', 'high'),
                445: ('SMB', 'high'),
                3389: ('RDP', 'high')
            }
            
            for port in scan_results['ports'].get('open_ports', []):
                if port in risky_ports:
                    service, severity = risky_ports[port]
                    score -= 15 if severity == 'critical' else 10
                    vulnerabilities.append({
                        'type': 'port',
                        'severity': severity,
                        'description': f'{service} port {port} is open'
                    })
        
        # DNS scoring
        if 'dns' in scan_results and scan_results['dns'].get('status') == 'completed':
            security_records = scan_results['dns'].get('security_records', {})
            if not security_records.get('SPF'):
                score -= 5
                vulnerabilities.append({
                    'type': 'dns',
                    'severity': 'low',
                    'description': 'No SPF record found'
                })
            if not security_records.get('DMARC'):
                score -= 5
                vulnerabilities.append({
                    'type': 'dns',
                    'severity': 'low',
                    'description': 'No DMARC record found'
                })
        
        # Header scoring
        if 'headers' in scan_results and scan_results['headers'].get('status') == 'completed':
            critical_headers = ['Strict-Transport-Security', 'X-Frame-Options', 'Content-Security-Policy']
            for header in scan_results['headers'].get('missing', []):
                if header in critical_headers:
                    score -= 10
                    vulnerabilities.append({
                        'type': 'header',
                        'severity': 'medium',
                        'description': f'Missing security header: {header}'
                    })
                else:
                    score -= 5
                    vulnerabilities.append({
                        'type': 'header',
                        'severity': 'low',
                        'description': f'Missing security header: {header}'
                    })
        
        # Vulnerability scoring
        if 'vulnerabilities' in scan_results and scan_results['vulnerabilities'].get('status') == 'completed':
            for vuln in scan_results['vulnerabilities'].get('vulnerabilities', []):
                if vuln['severity'] == 'critical':
                    score -= 25
                elif vuln['severity'] == 'high':
                    score -= 20
                elif vuln['severity'] == 'medium':
                    score -= 10
                else:
                    score -= 5
                vulnerabilities.append(vuln)
        
        # Enhanced DNS/Email security scoring
        if 'dns' in scan_results and scan_results['dns'].get('status') == 'completed':
            dns_results = scan_results['dns']
            security_records = dns_results.get('security_records', {})
            
            # SPF record scoring
            if not security_records.get('SPF'):
                score -= 10
                vulnerabilities.append({
                    'type': 'email',
                    'severity': 'medium',
                    'description': 'No SPF record found - email spoofing possible'
                })
            
            # DMARC record scoring
            if not security_records.get('DMARC'):
                score -= 15
                vulnerabilities.append({
                    'type': 'email',
                    'severity': 'high',
                    'description': 'No DMARC record found - advanced email protection missing'
                })
            
            # DKIM record scoring
            if not security_records.get('DKIM'):
                score -= 10
                vulnerabilities.append({
                    'type': 'email',
                    'severity': 'medium',
                    'description': 'No DKIM records found - email authentication incomplete'
                })
        
        # IP security scoring
        if ip_info:
            if ip_info.get('is_proxy') or ip_info.get('is_vpn'):
                score -= 20
                vulnerabilities.append({
                    'type': 'network',
                    'severity': 'high',
                    'description': 'Domain hosted behind VPN/Proxy - potential anonymization'
                })
            
            if ip_info.get('security_score', 100) < 80:
                score -= (100 - ip_info.get('security_score', 100)) / 5
                for issue in ip_info.get('issues', []):
                    vulnerabilities.append({
                        'type': 'network',
                        'severity': 'medium',
                        'description': f'IP security issue: {issue}'
                    })
        
        # New scans scoring
        
        # Subdomain scoring
        if 'subdomains' in scan_results and scan_results['subdomains'].get('status') == 'completed':
            subdomain_results = scan_results['subdomains']
            for vuln_sub in subdomain_results.get('vulnerable_subdomains', []):
                score -= 20
                vulnerabilities.append({
                    'type': 'subdomain',
                    'severity': 'high',
                    'description': f"Subdomain takeover vulnerability: {vuln_sub['subdomain']}"
                })
            if subdomain_results.get('wildcard_dns'):
                score -= 5
                vulnerabilities.append({
                    'type': 'subdomain',
                    'severity': 'low',
                    'description': 'Wildcard DNS enabled'
                })
        
        # Email security scoring
        if 'email_security' in scan_results and scan_results['email_security'].get('status') == 'completed':
            email_results = scan_results['email_security']
            email_sec = email_results.get('email_security', {})
            
            if not email_sec.get('mta_sts'):
                score -= 8
                vulnerabilities.append({
                    'type': 'email',
                    'severity': 'medium',
                    'description': 'No MTA-STS policy configured'
                })
            
            if not email_sec.get('bimi'):
                score -= 3
                vulnerabilities.append({
                    'type': 'email',
                    'severity': 'low',
                    'description': 'No BIMI record for brand protection'
                })
            
            # MX server security
            for mx in email_results.get('mx_records', []):
                if not mx.get('tls_capable'):
                    score -= 10
                    vulnerabilities.append({
                        'type': 'email',
                        'severity': 'medium',
                        'description': f"MX server {mx['host']} does not support TLS"
                    })
        
        # WAF scoring
        if 'waf' in scan_results and scan_results['waf'].get('status') == 'completed':
            waf_results = scan_results['waf']
            if not waf_results.get('waf_detected'):
                score -= 15
                vulnerabilities.append({
                    'type': 'waf',
                    'severity': 'high',
                    'description': 'No Web Application Firewall detected'
                })
            
            if not waf_results.get('rate_limiting', True):
                score -= 10
                vulnerabilities.append({
                    'type': 'waf',
                    'severity': 'medium',
                    'description': 'No rate limiting detected'
                })
        
        # Technology scoring
        if 'technology' in scan_results and scan_results['technology'].get('status') == 'completed':
            tech_results = scan_results['technology']
            for vuln in tech_results.get('vulnerabilities', []):
                if vuln['severity'] == 'critical':
                    score -= 25
                elif vuln['severity'] == 'high':
                    score -= 20
                elif vuln['severity'] == 'medium':
                    score -= 10
                else:
                    score -= 5
                vulnerabilities.append(vuln)
            
            for issue in tech_results.get('issues', []):
                score -= 3
                vulnerabilities.append({
                    'type': 'technology',
                    'severity': 'low',
                    'description': issue
                })
        
        # API security scoring
        if 'api_security' in scan_results and scan_results['api_security'].get('status') == 'completed':
            api_results = scan_results['api_security']
            for issue in api_results.get('issues', []):
                if 'authentication' in issue.lower():
                    score -= 15
                    severity = 'high'
                elif 'documentation' in issue.lower():
                    score -= 8
                    severity = 'medium'
                elif 'cors' in issue.lower():
                    score -= 10
                    severity = 'medium'
                elif 'introspection' in issue.lower():
                    score -= 12
                    severity = 'medium'
                else:
                    score -= 5
                    severity = 'low'
                
                vulnerabilities.append({
                    'type': 'api',
                    'severity': severity,
                    'description': issue
                })
        
        # Cloud misconfiguration scoring
        if 'cloud_misconfig' in scan_results and scan_results['cloud_misconfig'].get('status') == 'completed':
            cloud_results = scan_results['cloud_misconfig']
            for bucket in cloud_results.get('exposed_buckets', []):
                score -= 25
                vulnerabilities.append({
                    'type': 'cloud',
                    'severity': 'critical',
                    'description': f"Exposed {bucket['type']} bucket: {bucket['url']}"
                })
            
            for misconfig in cloud_results.get('misconfigurations', []):
                if misconfig.get('severity') == 'critical':
                    score -= 30
                    severity = 'critical'
                elif misconfig.get('severity') == 'high':
                    score -= 20
                    severity = 'high'
                else:
                    score -= 10
                    severity = 'medium'
                
                vulnerabilities.append({
                    'type': 'cloud',
                    'severity': severity,
                    'description': f"{misconfig['service']}: {misconfig['issue']}"
                })
        
        # Compliance scoring
        if 'compliance' in scan_results and scan_results['compliance'].get('status') == 'completed':
            compliance_results = scan_results['compliance']
            for issue in compliance_results.get('issues', []):
                if 'gdpr' in issue.lower():
                    score -= 12
                    severity = 'high'
                elif 'pci' in issue.lower():
                    score -= 15
                    severity = 'high'
                elif 'hipaa' in issue.lower():
                    score -= 18
                    severity = 'critical'
                else:
                    score -= 5
                    severity = 'low'
                
                vulnerabilities.append({
                    'type': 'compliance',
                    'severity': severity,
                    'description': issue
                })
        
        # Performance security scoring
        if 'performance' in scan_results and scan_results['performance'].get('status') == 'completed':
            perf_results = scan_results['performance']
            
            # Mixed content is a security issue
            if perf_results.get('mixed_content'):
                score -= 15
                vulnerabilities.append({
                    'type': 'performance',
                    'severity': 'high',
                    'description': f"Mixed content detected: {len(perf_results['mixed_content'])} insecure resources"
                })
            
            # Subresource integrity missing
            sri_issues = perf_results.get('resource_integrity', [])
            if sri_issues:
                score -= min(10, len(sri_issues) * 2)
                vulnerabilities.append({
                    'type': 'performance',
                    'severity': 'medium',
                    'description': f"Subresource Integrity missing on {len(sri_issues)} external resources"
                })
            
            # Other performance security issues
            for impact in perf_results.get('security_impact', []):
                score -= 5
                vulnerabilities.append({
                    'type': 'performance',
                    'severity': 'medium',
                    'description': impact
                })

        return max(0, score), vulnerabilities
    
    def _clean_domain(self, domain: str) -> str:
        """Clean and validate domain"""
        # Remove protocol if present
        domain = re.sub(r'^https?://', '', domain)
        # Remove path if present
        domain = domain.split('/')[0]
        # Remove port if present
        domain = domain.split(':')[0]
        # Remove www. if present
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain.lower().strip()
    
    def _get_ip_info(self, domain: str) -> Dict[str, Any]:
        """Get IP information for the domain"""
        ip_info = {
            'ip': None,
            'hostname': None,
            'is_vpn': False,
            'is_proxy': False,
            'is_tor': False,
            'is_hosting': False,
            'country': None,
            'city': None,
            'org': None,
            'asn': None,
            'security_score': 100,
            'issues': []
        }
        
        try:
            # Get IP address
            ip = socket.gethostbyname(domain)
            ip_info['ip'] = ip
            
            # Get reverse DNS
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                ip_info['hostname'] = hostname
            except:
                ip_info['hostname'] = 'No reverse DNS'
            
            # Check common VPN/proxy patterns in hostname
            vpn_patterns = ['vpn', 'proxy', 'tor', 'relay', 'anonymize', 'hide']
            hosting_patterns = ['amazonaws', 'googleusercontent', 'azure', 'digitalocean', 'linode', 'vultr']
            
            hostname_lower = (ip_info['hostname'] or '').lower()
            for pattern in vpn_patterns:
                if pattern in hostname_lower:
                    ip_info['is_vpn'] = True
                    ip_info['security_score'] -= 20
                    ip_info['issues'].append(f'Possible VPN/Proxy detected: {pattern} in hostname')
            
            for pattern in hosting_patterns:
                if pattern in hostname_lower:
                    ip_info['is_hosting'] = True
                    ip_info['issues'].append(f'Hosted on cloud platform: {pattern}')
            
            # Try to get geo info via ip-api.com (free tier)
            try:
                geo_response = self.session.get(f'http://ip-api.com/json/{ip}', timeout=5)
                if geo_response.status_code == 200:
                    geo_data = geo_response.json()
                    if geo_data.get('status') == 'success':
                        ip_info['country'] = geo_data.get('country')
                        ip_info['city'] = geo_data.get('city')
                        ip_info['org'] = geo_data.get('org')
                        ip_info['asn'] = geo_data.get('as')
                        
                        # Check if it's a known VPN/proxy
                        if geo_data.get('proxy'):
                            ip_info['is_proxy'] = True
                            ip_info['security_score'] -= 30
                            ip_info['issues'].append('IP identified as proxy/VPN')
            except:
                pass
            
        except socket.gaierror:
            ip_info['issues'].append('Could not resolve domain to IP')
            ip_info['security_score'] -= 50
        except Exception as e:
            ip_info['issues'].append(f'IP lookup error: {str(e)}')
        
        return ip_info
    
    def scan_subdomains(self, domain: str) -> Dict[str, Any]:
        """Scan for subdomains and check for takeover vulnerabilities"""
        results = {
            'status': 'completed',
            'subdomains': [],
            'vulnerable_subdomains': [],
            'issues': []
        }
        
        try:
            # Common subdomain prefixes to check
            common_subdomains = [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
                'blog', 'app', 'api', 'dev', 'staging', 'test', 'demo', 'admin', 'portal',
                'secure', 'vpn', 'remote', 'cloud', 'git', 'shop', 'store', 'm', 'mobile',
                'help', 'support', 'docs', 'beta', 'alpha', 'stage', 'v1', 'v2', 'api-v1',
                'cdn', 'static', 'assets', 'images', 'img', 'media', 'upload', 'downloads',
                'files', 'backup', 'old', 'new', 'portal', 'gateway', 'proxy', 'service'
            ]
            
            found_subdomains = []
            
            # Check each subdomain
            for subdomain in common_subdomains:
                check_domain = f"{subdomain}.{domain}"
                try:
                    # Try to resolve the subdomain
                    socket.gethostbyname(check_domain)
                    found_subdomains.append({
                        'subdomain': check_domain,
                        'resolved': True
                    })
                except socket.gaierror:
                    # Check for potential subdomain takeover
                    try:
                        # Check CNAME records for dangling references
                        resolver = dns.resolver.Resolver()
                        resolver.timeout = 2
                        answers = resolver.resolve(check_domain, 'CNAME')
                        for rdata in answers:
                            cname = str(rdata)
                            # Check for common vulnerable patterns
                            vulnerable_patterns = [
                                'herokuapp.com', 'azurewebsites.net', 'cloudapp.net',
                                'cloudfront.net', 's3.amazonaws.com', 'github.io',
                                'unbouncepages.com', 'tumblr.com', 'wpengine.com'
                            ]
                            for pattern in vulnerable_patterns:
                                if pattern in cname:
                                    try:
                                        # Verify if the target doesn't exist
                                        socket.gethostbyname(cname.rstrip('.'))
                                    except socket.gaierror:
                                        results['vulnerable_subdomains'].append({
                                            'subdomain': check_domain,
                                            'cname': cname,
                                            'vulnerability': 'Potential subdomain takeover',
                                            'service': pattern
                                        })
                                        results['issues'].append(
                                            f'Potential subdomain takeover on {check_domain} pointing to {cname}'
                                        )
                    except:
                        pass
            
            results['subdomains'] = found_subdomains
            
            # Check wildcard DNS
            try:
                wildcard_check = f"definitely-not-existing-{int(time.time())}.{domain}"
                socket.gethostbyname(wildcard_check)
                results['wildcard_dns'] = True
                results['issues'].append('Wildcard DNS enabled - all subdomains resolve')
            except:
                results['wildcard_dns'] = False
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def scan_email_security(self, domain: str) -> Dict[str, Any]:
        """Deep scan of email security configuration"""
        results = {
            'status': 'completed',
            'mx_records': [],
            'email_security': {
                'spf': None,
                'dmarc': None,
                'dkim': {},
                'bimi': None,
                'mta_sts': None,
                'tls_rpt': None
            },
            'issues': [],
            'mx_security': []
        }
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            
            # Get MX records
            try:
                mx_answers = resolver.resolve(domain, 'MX')
                for rdata in mx_answers:
                    mx_host = str(rdata.exchange).rstrip('.')
                    mx_info = {
                        'priority': rdata.preference,
                        'host': mx_host,
                        'tls_capable': False,
                        'tls_version': None
                    }
                    
                    # Check if MX server supports TLS
                    try:
                        context = ssl.create_default_context()
                        with socket.create_connection((mx_host, 25), timeout=5) as sock:
                            # SMTP greeting
                            sock.recv(1024)
                            sock.send(b'EHLO test.com\r\n')
                            response = sock.recv(1024).decode('utf-8', errors='ignore')
                            
                            if 'STARTTLS' in response:
                                mx_info['tls_capable'] = True
                                # Try to initiate TLS
                                sock.send(b'STARTTLS\r\n')
                                sock.recv(1024)
                                try:
                                    with context.wrap_socket(sock, server_hostname=mx_host) as ssock:
                                        mx_info['tls_version'] = ssock.version()
                                except:
                                    mx_info['tls_version'] = 'TLS initiation failed'
                    except:
                        pass
                    
                    results['mx_records'].append(mx_info)
                    
                    if not mx_info['tls_capable']:
                        results['issues'].append(f"MX server {mx_host} does not support TLS encryption")
            except dns.resolver.NXDOMAIN:
                results['issues'].append('No MX records found')
            except Exception as e:
                results['issues'].append(f'MX lookup failed: {str(e)}')
            
            # Check SPF
            try:
                txt_answers = resolver.resolve(domain, 'TXT')
                for rdata in txt_answers:
                    txt_record = str(rdata).strip('"')
                    if txt_record.startswith('v=spf1'):
                        results['email_security']['spf'] = txt_record
                        # Validate SPF record
                        if '-all' not in txt_record and '~all' not in txt_record:
                            results['issues'].append('SPF record does not have a strict policy')
            except:
                pass
            
            # Check DMARC
            try:
                dmarc_answers = resolver.resolve(f'_dmarc.{domain}', 'TXT')
                for rdata in dmarc_answers:
                    txt_record = str(rdata).strip('"')
                    if txt_record.startswith('v=DMARC1'):
                        results['email_security']['dmarc'] = txt_record
                        # Parse DMARC policy
                        if 'p=none' in txt_record:
                            results['issues'].append('DMARC policy is set to "none" - not enforcing')
                        if 'pct=' in txt_record:
                            pct_match = re.search(r'pct=(\d+)', txt_record)
                            if pct_match and int(pct_match.group(1)) < 100:
                                results['issues'].append(f'DMARC only applied to {pct_match.group(1)}% of emails')
            except:
                pass
            
            # Check DKIM with more selectors
            dkim_selectors = [
                'default', 'google', 'k1', 'k2', 'k3', 'selector1', 'selector2',
                'mail', 'email', 'dkim', 's1', 's2', 'mandrill', 'mailgun', 'sendgrid',
                'zendesk1', 'zendesk2', 'facebook', 'amazonses', 'pm', 'mc1', 'mc2'
            ]
            
            for selector in dkim_selectors:
                try:
                    dkim_answers = resolver.resolve(f'{selector}._domainkey.{domain}', 'TXT')
                    for rdata in dkim_answers:
                        txt_record = str(rdata).strip('"')
                        if 'p=' in txt_record:
                            results['email_security']['dkim'][selector] = 'Present'
                except:
                    continue
            
            # Check BIMI
            try:
                bimi_answers = resolver.resolve(f'default._bimi.{domain}', 'TXT')
                for rdata in bimi_answers:
                    txt_record = str(rdata).strip('"')
                    if txt_record.startswith('v=BIMI1'):
                        results['email_security']['bimi'] = txt_record
            except:
                pass
            
            # Check MTA-STS
            try:
                mta_sts_response = self.session.get(
                    f'https://mta-sts.{domain}/.well-known/mta-sts.txt',
                    timeout=5
                )
                if mta_sts_response.status_code == 200:
                    results['email_security']['mta_sts'] = 'Present'
            except:
                pass
            
            # Check TLS-RPT
            try:
                tlsrpt_answers = resolver.resolve(f'_smtp._tls.{domain}', 'TXT')
                for rdata in tlsrpt_answers:
                    txt_record = str(rdata).strip('"')
                    if 'v=TLSRPTv1' in txt_record:
                        results['email_security']['tls_rpt'] = txt_record
            except:
                pass
            
            # Add issues for missing records
            if not results['email_security']['spf']:
                results['issues'].append('No SPF record found - email spoofing possible')
            if not results['email_security']['dmarc']:
                results['issues'].append('No DMARC record found - no email authentication policy')
            if not results['email_security']['dkim']:
                results['issues'].append('No DKIM records found - email integrity not verified')
            if not results['email_security']['mta_sts']:
                results['issues'].append('No MTA-STS policy - email transport security not enforced')
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results    
    def scan_waf(self, domain: str) -> Dict[str, Any]:
        """Detect Web Application Firewall presence"""
        results = {
            'status': 'completed',
            'waf_detected': False,
            'waf_vendor': None,
            'detection_methods': [],
            'issues': []
        }
        
        try:
            base_url = f'https://{domain}'
            
            # WAF detection signatures
            waf_signatures = {
                'Cloudflare': {
                    'headers': ['CF-RAY', 'CF-Cache-Status'],
                    'cookies': ['__cfduid', 'cf_clearance'],
                    'server': ['cloudflare']
                },
                'AWS WAF': {
                    'headers': ['X-AMZ-CF-ID', 'X-AMZ-ID-2'],
                    'server': ['AmazonS3', 'CloudFront']
                },
                'Akamai': {
                    'headers': ['X-Akamai-Transformed'],
                    'server': ['AkamaiGHost']
                },
                'Sucuri': {
                    'headers': ['X-Sucuri-ID', 'X-Sucuri-Cache'],
                    'server': ['Sucuri/Cloudproxy']
                },
                'Incapsula': {
                    'headers': ['X-Iinfo'],
                    'cookies': ['incap_ses', 'visid_incap']
                },
                'F5 BIG-IP': {
                    'headers': ['X-Cnection'],
                    'cookies': ['BIGipServer'],
                    'server': ['BigIP', 'F5']
                },
                'Barracuda': {
                    'headers': ['X-BCP'],
                    'server': ['Barracuda']
                },
                'ModSecurity': {
                    'headers': ['X-Mod-Security'],
                    'server': ['Mod_Security']
                }
            }
            
            # Normal request
            try:
                response = self.session.get(base_url, timeout=10)
                headers = dict(response.headers)
                cookies = response.cookies
                server = headers.get('Server', '').lower()
                
                # Check signatures
                for waf_name, signatures in waf_signatures.items():
                    detected = False
                    
                    # Check headers
                    if 'headers' in signatures:
                        for header in signatures['headers']:
                            if header in headers:
                                detected = True
                                results['detection_methods'].append(f'Header: {header}')
                                break
                    
                    # Check cookies
                    if 'cookies' in signatures and not detected:
                        for cookie in signatures['cookies']:
                            if cookie in cookies:
                                detected = True
                                results['detection_methods'].append(f'Cookie: {cookie}')
                                break
                    
                    # Check server header
                    if 'server' in signatures and not detected:
                        for server_sig in signatures['server']:
                            if server_sig.lower() in server:
                                detected = True
                                results['detection_methods'].append(f'Server: {server}')
                                break
                    
                    if detected:
                        results['waf_detected'] = True
                        results['waf_vendor'] = waf_name
                        break
                
                # Try malicious payloads to trigger WAF
                if not results['waf_detected']:
                    payloads = [
                        '/?test=<script>alert(1)</script>',
                        '/?id=1 OR 1=1',
                        '/?file=../../../../etc/passwd',
                        '/?cmd=whoami'
                    ]
                    
                    for payload in payloads:
                        try:
                            mal_response = self.session.get(base_url + payload, timeout=5)
                            
                            # Check for WAF block pages
                            if mal_response.status_code in [403, 406, 419, 429, 503]:
                                body_lower = mal_response.text.lower()
                                
                                waf_indicators = {
                                    'cloudflare': ['cloudflare', 'ray id'],
                                    'aws waf': ['request blocked', 'aws'],
                                    'modsecurity': ['mod_security', 'modsecurity'],
                                    'generic': ['blocked', 'forbidden', 'detected', 'denied']
                                }
                                
                                for waf, indicators in waf_indicators.items():
                                    for indicator in indicators:
                                        if indicator in body_lower:
                                            results['waf_detected'] = True
                                            results['waf_vendor'] = waf.title() if waf != 'generic' else 'Unknown'
                                            results['detection_methods'].append(
                                                f'Block page triggered by payload: {payload}'
                                            )
                                            break
                                    if results['waf_detected']:
                                        break
                            
                            if results['waf_detected']:
                                break
                                
                        except:
                            pass
            
            except Exception as e:
                results['issues'].append(f'WAF detection error: {str(e)}')
            
            # Rate limiting check
            try:
                start_time = time.time()
                for i in range(10):
                    self.session.get(base_url, timeout=2)
                
                elapsed = time.time() - start_time
                if elapsed > 15:  # If requests took too long, likely rate limited
                    results['rate_limiting'] = True
                    results['issues'].append('Rate limiting detected')
                else:
                    results['rate_limiting'] = False
            except:
                pass
            
            if not results['waf_detected']:
                results['issues'].append('No WAF detected - consider implementing one')
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def scan_technology(self, domain: str) -> Dict[str, Any]:
        """Detect CMS, frameworks, and technology stack"""
        results = {
            'status': 'completed',
            'cms': None,
            'frameworks': [],
            'javascript_libraries': [],
            'server_technologies': [],
            'vulnerabilities': [],
            'issues': []
        }
        
        try:
            base_url = f'https://{domain}'
            response = self.session.get(base_url, timeout=10)
            headers = dict(response.headers)
            body = response.text
            soup = BeautifulSoup(body, 'html.parser')
            
            # CMS Detection
            cms_signatures = {
                'WordPress': {
                    'meta': {'name': 'generator', 'content': 'WordPress'},
                    'paths': ['/wp-admin/', '/wp-content/', '/wp-includes/'],
                    'headers': {'X-Powered-By': 'W3 Total Cache'}
                },
                'Joomla': {
                    'meta': {'name': 'generator', 'content': 'Joomla'},
                    'paths': ['/administrator/', '/components/', '/modules/'],
                    'text': ['Joomla!']
                },
                'Drupal': {
                    'meta': {'name': 'generator', 'content': 'Drupal'},
                    'headers': {'X-Generator': 'Drupal'},
                    'paths': ['/core/', '/sites/default/']
                },
                'Shopify': {
                    'meta': {'name': 'generator', 'content': 'Shopify'},
                    'text': ['cdn.shopify.com']
                },
                'Wix': {
                    'meta': {'name': 'generator', 'content': 'Wix.com'},
                    'text': ['static.wixstatic.com']
                },
                'Squarespace': {
                    'text': ['static.squarespace.com']
                },
                'Magento': {
                    'paths': ['/skin/frontend/', '/js/mage/'],
                    'cookies': ['frontend', 'adminhtml']
                }
            }
            
            # Check for CMS
            for cms_name, signatures in cms_signatures.items():
                detected = False
                
                # Check meta tags
                if 'meta' in signatures:
                    meta_tag = soup.find('meta', signatures['meta'])
                    if meta_tag:
                        results['cms'] = cms_name
                        detected = True
                
                # Check paths
                if 'paths' in signatures and not detected:
                    for path in signatures['paths']:
                        if path in body:
                            results['cms'] = cms_name
                            detected = True
                            break
                
                # Check text content
                if 'text' in signatures and not detected:
                    for text in signatures['text']:
                        if text in body:
                            results['cms'] = cms_name
                            detected = True
                            break
                
                if detected:
                    # Check for version
                    version_patterns = {
                        'WordPress': r'WordPress (\d+\.\d+\.?\d*)',
                        'Joomla': r'Joomla! (\d+\.\d+\.?\d*)',
                        'Drupal': r'Drupal (\d+\.\d+\.?\d*)'
                    }
                    
                    if cms_name in version_patterns:
                        version_match = re.search(version_patterns[cms_name], body)
                        if version_match:
                            version = version_match.group(1)
                            results['cms'] = f'{cms_name} {version}'
                            
                            # Check for outdated versions
                            outdated_versions = {
                                'WordPress': '6.0',
                                'Joomla': '4.0',
                                'Drupal': '9.0'
                            }
                            
                            if cms_name in outdated_versions:
                                try:
                                    current = float('.'.join(version.split('.')[:2]))
                                    minimum = float(outdated_versions[cms_name])
                                    if current < minimum:
                                        results['vulnerabilities'].append({
                                            'type': 'outdated_cms',
                                            'severity': 'high',
                                            'description': f'Outdated {cms_name} version {version} detected'
                                        })
                                except:
                                    pass
                    break
            
            # JavaScript Libraries Detection
            js_patterns = {
                'jQuery': [r'jquery[.-]?([\d.]+)?\.js', r'jQuery v?([\d.]+)'],
                'React': [r'react[.-]?([\d.]+)?\.js', r'React v?([\d.]+)'],
                'Angular': [r'angular[.-]?([\d.]+)?\.js', r'Angular v?([\d.]+)'],
                'Vue.js': [r'vue[.-]?([\d.]+)?\.js', r'Vue.js v?([\d.]+)'],
                'Bootstrap': [r'bootstrap[.-]?([\d.]+)?\.js', r'Bootstrap v?([\d.]+)']
            }
            
            for lib_name, patterns in js_patterns.items():
                for pattern in patterns:
                    match = re.search(pattern, body, re.IGNORECASE)
                    if match:
                        version = match.group(1) if match.groups() else 'Unknown'
                        results['javascript_libraries'].append(f'{lib_name} {version}')
                        break
            
            # Server Technology Detection
            server_header = headers.get('Server', '')
            if server_header:
                results['server_technologies'].append(server_header)
            
            powered_by = headers.get('X-Powered-By', '')
            if powered_by:
                results['server_technologies'].append(powered_by)
            
            # Framework Detection
            framework_signatures = {
                'Laravel': ['laravel_session', 'XSRF-TOKEN'],
                'Django': ['csrftoken', 'django'],
                'Ruby on Rails': ['_rails_session', 'rails'],
                'ASP.NET': ['ASP.NET_SessionId', 'aspnet'],
                'Express.js': ['connect.sid', 'express']
            }
            
            cookies = response.cookies
            for framework, signatures in framework_signatures.items():
                for sig in signatures:
                    if sig in str(cookies) or sig in body.lower():
                        results['frameworks'].append(framework)
                        break
            
            # Check for exposed version files
            version_files = [
                '/version.txt', '/VERSION', '/readme.html', '/README.md',
                '/CHANGELOG.md', '/changelog.txt', '/release-notes.txt'
            ]
            
            for file in version_files:
                try:
                    ver_response = self.session.get(base_url + file, timeout=5)
                    if ver_response.status_code == 200:
                        results['issues'].append(f'Version file exposed: {file}')
                except:
                    pass
            
            # Check for outdated libraries
            outdated_patterns = {
                'jQuery 1.': 'Outdated jQuery 1.x detected',
                'jQuery 2.': 'Outdated jQuery 2.x detected',
                'Angular 1.': 'Outdated AngularJS 1.x detected',
                'Bootstrap 2.': 'Outdated Bootstrap 2.x detected',
                'Bootstrap 3.': 'Outdated Bootstrap 3.x detected'
            }
            
            for pattern, issue in outdated_patterns.items():
                if pattern in body:
                    results['issues'].append(issue)
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def scan_api_security(self, domain: str) -> Dict[str, Any]:
        """Scan for API endpoints and security issues"""
        results = {
            'status': 'completed',
            'api_endpoints': [],
            'api_docs': [],
            'authentication': [],
            'issues': []
        }
        
        try:
            base_url = f'https://{domain}'
            
            # Common API paths to check
            api_paths = [
                '/api', '/api/v1', '/api/v2', '/api/v3',
                '/v1', '/v2', '/v3',
                '/graphql', '/graphiql',
                '/swagger', '/swagger-ui', '/swagger.json', '/api-docs',
                '/openapi', '/openapi.json',
                '/.well-known/openapi.json',
                '/redoc', '/docs', '/api/docs',
                '/rest', '/rest/v1', '/rest/v2',
                '/services', '/webservice', '/ws',
                '/json', '/jsonapi', '/json-api',
                '/odata', '/data', '/query'
            ]
            
            for path in api_paths:
                try:
                    response = self.session.get(base_url + path, timeout=5)
                    if response.status_code == 200:
                        content_type = response.headers.get('Content-Type', '')
                        
                        # Check if it's an API endpoint
                        if 'json' in content_type or 'xml' in content_type:
                            results['api_endpoints'].append({
                                'path': path,
                                'status': response.status_code,
                                'content_type': content_type
                            })
                            
                            # Check for authentication
                            auth_headers = ['Authorization', 'X-API-Key', 'API-Key', 'X-Auth-Token']
                            requires_auth = any(header in response.headers for header in auth_headers)
                            
                            if not requires_auth and response.status_code == 200:
                                results['issues'].append(f'API endpoint {path} accessible without authentication')
                        
                        # Check for API documentation
                        if any(doc in path for doc in ['swagger', 'docs', 'openapi', 'graphiql']):
                            results['api_docs'].append({
                                'path': path,
                                'type': 'documentation',
                                'accessible': True
                            })
                            results['issues'].append(f'API documentation exposed at {path}')
                            
                    elif response.status_code == 401:
                        results['authentication'].append({
                            'path': path,
                            'method': response.headers.get('WWW-Authenticate', 'Unknown')
                        })
                        
                except:
                    continue
            
            # Check for GraphQL introspection
            try:
                graphql_introspection = {
                    "query": "{ __schema { types { name } } }"
                }
                response = self.session.post(
                    f'{base_url}/graphql',
                    json=graphql_introspection,
                    timeout=5
                )
                if response.status_code == 200 and '__schema' in response.text:
                    results['issues'].append('GraphQL introspection is enabled')
                    results['api_endpoints'].append({
                        'path': '/graphql',
                        'type': 'GraphQL',
                        'introspection_enabled': True
                    })
            except:
                pass
            
            # Check for common API misconfigurations
            # CORS check
            try:
                headers = {'Origin': 'https://evil.com'}
                response = self.session.options(base_url, headers=headers, timeout=5)
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                if acao == '*' or acao == 'https://evil.com':
                    results['issues'].append(f'Permissive CORS policy on API: {acao}')
            except:
                pass
            
            # Rate limiting check
            api_endpoint = results['api_endpoints'][0]['path'] if results['api_endpoints'] else '/api'
            try:
                start_time = time.time()
                for i in range(20):
                    self.session.get(base_url + api_endpoint, timeout=2)
                elapsed = time.time() - start_time
                
                if elapsed < 5:  # 20 requests in under 5 seconds
                    results['issues'].append('No rate limiting detected on API endpoints')
            except:
                pass
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def scan_cloud_misconfig(self, domain: str) -> Dict[str, Any]:
        """Scan for cloud service misconfigurations"""
        results = {
            'status': 'completed',
            'cloud_services': [],
            'exposed_buckets': [],
            'misconfigurations': [],
            'issues': []
        }
        
        try:
            # Check for S3 buckets
            s3_patterns = [
                f'{domain}.s3.amazonaws.com',
                f's3.amazonaws.com/{domain}',
                f'{domain}-assets.s3.amazonaws.com',
                f'{domain}-backup.s3.amazonaws.com',
                f'{domain}-www.s3.amazonaws.com',
                f'{domain}-public.s3.amazonaws.com',
                f'{domain}-private.s3.amazonaws.com',
                f'{domain}-logs.s3.amazonaws.com',
                f'{domain}-media.s3.amazonaws.com'
            ]
            
            for bucket_url in s3_patterns:
                try:
                    response = self.session.get(f'https://{bucket_url}', timeout=5)
                    if response.status_code == 200:
                        if '<?xml' in response.text and 'ListBucketResult' in response.text:
                            results['exposed_buckets'].append({
                                'url': bucket_url,
                                'type': 'S3',
                                'listing_enabled': True
                            })
                            results['issues'].append(f'S3 bucket with directory listing enabled: {bucket_url}')
                        else:
                            results['cloud_services'].append({
                                'url': bucket_url,
                                'type': 'S3',
                                'accessible': True
                            })
                    elif response.status_code == 403:
                        results['cloud_services'].append({
                            'url': bucket_url,
                            'type': 'S3',
                            'accessible': False
                        })
                except:
                    continue
            
            # Check for Azure Blob Storage
            azure_patterns = [
                f'{domain}.blob.core.windows.net',
                f'{domain}.file.core.windows.net',
                f'{domain}storage.blob.core.windows.net'
            ]
            
            for azure_url in azure_patterns:
                try:
                    response = self.session.get(f'https://{azure_url}', timeout=5)
                    if response.status_code == 200:
                        results['cloud_services'].append({
                            'url': azure_url,
                            'type': 'Azure',
                            'accessible': True
                        })
                        if 'BlobType' in response.text:
                            results['issues'].append(f'Azure storage container accessible: {azure_url}')
                except:
                    continue
            
            # Check for Google Cloud Storage
            gcs_patterns = [
                f'{domain}.storage.googleapis.com',
                f'storage.googleapis.com/{domain}',
                f'{domain}-assets.storage.googleapis.com'
            ]
            
            for gcs_url in gcs_patterns:
                try:
                    response = self.session.get(f'https://{gcs_url}', timeout=5)
                    if response.status_code == 200:
                        results['cloud_services'].append({
                            'url': gcs_url,
                            'type': 'GCS',
                            'accessible': True
                        })
                        if '<?xml' in response.text:
                            results['issues'].append(f'Google Cloud Storage bucket accessible: {gcs_url}')
                except:
                    continue
            
            # Check for exposed Firebase databases
            firebase_patterns = [
                f'{domain}.firebaseio.com/.json',
                f'{domain}-default-rtdb.firebaseio.com/.json',
                f'{domain}.firebaseapp.com/.json'
            ]
            
            for firebase_url in firebase_patterns:
                try:
                    response = self.session.get(f'https://{firebase_url}', timeout=5)
                    if response.status_code == 200:
                        try:
                            json_data = response.json()
                            if json_data:
                                results['misconfigurations'].append({
                                    'service': 'Firebase',
                                    'issue': 'Database publicly readable',
                                    'url': firebase_url
                                })
                                results['issues'].append(f'Firebase database publicly accessible: {firebase_url}')
                        except:
                            pass
                except:
                    continue
            
            # Check for exposed Docker Registry
            try:
                docker_response = self.session.get(f'https://{domain}/v2/', timeout=5)
                if docker_response.status_code == 200:
                    results['misconfigurations'].append({
                        'service': 'Docker Registry',
                        'issue': 'Registry API accessible',
                        'severity': 'high'
                    })
                    results['issues'].append('Docker Registry API exposed')
            except:
                pass
            
            # Check for Kubernetes API
            k8s_paths = ['/api', '/api/v1', '/apis', '/healthz', '/metrics']
            for path in k8s_paths:
                try:
                    response = self.session.get(f'https://{domain}:6443{path}', timeout=3)
                    if response.status_code in [200, 401, 403] and 'kubernetes' in response.text.lower():
                        results['misconfigurations'].append({
                            'service': 'Kubernetes',
                            'issue': f'API endpoint exposed at {path}',
                            'severity': 'critical'
                        })
                        results['issues'].append(f'Kubernetes API exposed at port 6443{path}')
                        break
                except:
                    continue
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def scan_compliance(self, domain: str) -> Dict[str, Any]:
        """Check for compliance-related security configurations"""
        results = {
            'status': 'completed',
            'gdpr': {},
            'pci': {},
            'hipaa': {},
            'general': {},
            'issues': []
        }
        
        try:
            base_url = f'https://{domain}'
            response = self.session.get(base_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # GDPR Compliance Checks
            gdpr_checks = {
                'privacy_policy': False,
                'cookie_notice': False,
                'data_retention': False,
                'third_party_tracking': []
            }
            
            # Check for privacy policy
            privacy_links = soup.find_all('a', href=re.compile(r'privacy|datenschutz|politique', re.I))
            if privacy_links:
                gdpr_checks['privacy_policy'] = True
                results['gdpr']['privacy_policy'] = 'Found'
            else:
                results['issues'].append('No privacy policy link found (GDPR requirement)')
            
            # Check for cookie notice
            cookie_keywords = ['cookie', 'consent', 'gdpr', 'accept cookies']
            page_text = response.text.lower()
            if any(keyword in page_text for keyword in cookie_keywords):
                gdpr_checks['cookie_notice'] = True
                results['gdpr']['cookie_notice'] = 'Present'
            else:
                results['issues'].append('No cookie consent notice found (GDPR requirement)')
            
            # Check for third-party tracking
            tracking_domains = [
                'google-analytics.com', 'googletagmanager.com', 'facebook.com/tr',
                'doubleclick.net', 'scorecardresearch.com', 'quantserve.com',
                'amazon-adsystem.com', 'googlesyndication.com', 'pinterest.com',
                'linkedin.com/li/', 'twitter.com/i/', 'hotjar.com'
            ]
            
            for domain_pattern in tracking_domains:
                if domain_pattern in response.text:
                    gdpr_checks['third_party_tracking'].append(domain_pattern)
            
            if gdpr_checks['third_party_tracking']:
                results['gdpr']['third_party_tracking'] = gdpr_checks['third_party_tracking']
                if not gdpr_checks['cookie_notice']:
                    results['issues'].append('Third-party tracking detected without cookie consent')
            
            # PCI DSS Basic Checks
            pci_checks = {
                'https_enabled': response.url.startswith('https'),
                'secure_headers': True,
                'form_security': True
            }
            
            # Check if HTTPS is enforced
            if not pci_checks['https_enabled']:
                results['issues'].append('HTTPS not enforced (PCI DSS requirement)')
                pci_checks['secure_headers'] = False
            
            # Check for payment forms
            payment_forms = soup.find_all('form')
            payment_keywords = ['card', 'payment', 'checkout', 'billing']
            
            for form in payment_forms:
                form_text = str(form).lower()
                if any(keyword in form_text for keyword in payment_keywords):
                    # Check if form uses HTTPS action
                    action = form.get('action', '')
                    if action and not (action.startswith('https') or action.startswith('/')):
                        pci_checks['form_security'] = False
                        results['issues'].append('Payment form not using HTTPS (PCI DSS violation)')
                    
                    # Check for autocomplete on sensitive fields
                    sensitive_inputs = form.find_all('input', {'name': re.compile(r'card|cvv|cvc|ccv', re.I)})
                    for input_field in sensitive_inputs:
                        if input_field.get('autocomplete') != 'off':
                            results['issues'].append('Credit card field allows autocomplete (PCI DSS issue)')
            
            results['pci'] = pci_checks
            
            # HIPAA Basic Checks (if healthcare-related)
            healthcare_keywords = ['patient', 'medical', 'health', 'clinic', 'doctor', 'hospital']
            is_healthcare = any(keyword in page_text for keyword in healthcare_keywords)
            
            if is_healthcare:
                hipaa_checks = {
                    'encryption': pci_checks['https_enabled'],
                    'privacy_notice': gdpr_checks['privacy_policy'],
                    'secure_forms': True
                }
                
                # Check for patient portals
                portal_keywords = ['patient portal', 'login', 'sign in']
                portal_found = any(keyword in page_text for keyword in portal_keywords)
                
                if portal_found and not pci_checks['https_enabled']:
                    hipaa_checks['secure_forms'] = False
                    results['issues'].append('Patient portal not using HTTPS (HIPAA violation)')
                
                results['hipaa'] = hipaa_checks
            
            # General Security Compliance
            general_checks = {
                'security_txt': False,
                'terms_of_service': False,
                'accessibility': False
            }
            
            # Check for security.txt
            try:
                sec_response = self.session.get(f'{base_url}/.well-known/security.txt', timeout=5)
                if sec_response.status_code == 200:
                    general_checks['security_txt'] = True
                    results['general']['security_txt'] = 'Present'
            except:
                pass
            
            # Check for terms of service
            tos_links = soup.find_all('a', href=re.compile(r'terms|tos|conditions', re.I))
            if tos_links:
                general_checks['terms_of_service'] = True
                results['general']['terms_of_service'] = 'Found'
            
            # Basic accessibility check
            alt_texts = soup.find_all('img', alt=True)
            images = soup.find_all('img')
            if images and len(alt_texts) / len(images) > 0.8:
                general_checks['accessibility'] = True
                results['general']['accessibility'] = 'Good alt text coverage'
            
            results['general'] = general_checks
            
            # SOC 2 Indicators
            soc2_indicators = {
                'security_headers': len(results.get('missing', [])) == 0,
                'encryption': pci_checks['https_enabled'],
                'monitoring': 'security.txt' in str(general_checks)
            }
            results['soc2_indicators'] = soc2_indicators
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def scan_performance(self, domain: str) -> Dict[str, Any]:
        """Scan for performance and security-related performance issues"""
        results = {
            'status': 'completed',
            'load_time': None,
            'security_impact': [],
            'mixed_content': [],
            'resource_integrity': [],
            'issues': []
        }
        
        try:
            base_url = f'https://{domain}'
            
            # Measure page load time
            start_time = time.time()
            response = self.session.get(base_url, timeout=15)
            load_time = time.time() - start_time
            results['load_time'] = round(load_time, 2)
            
            if load_time > 5:
                results['issues'].append(f'Slow page load time: {load_time}s (may indicate DDoS vulnerability)')
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for mixed content
            if response.url.startswith('https'):
                # Find all resource URLs
                resource_tags = [
                    ('img', 'src'), ('script', 'src'), ('link', 'href'),
                    ('iframe', 'src'), ('source', 'src'), ('embed', 'src')
                ]
                
                for tag, attr in resource_tags:
                    elements = soup.find_all(tag, {attr: True})
                    for element in elements:
                        url = element.get(attr)
                        if url and url.startswith('http://'):
                            results['mixed_content'].append({
                                'tag': tag,
                                'url': url[:100] + '...' if len(url) > 100 else url
                            })
                            
                if results['mixed_content']:
                    results['issues'].append(f"Mixed content detected: {len(results['mixed_content'])} insecure resources")
                    results['security_impact'].append('Mixed content weakens HTTPS security')
            
            # Check for Subresource Integrity (SRI)
            external_scripts = soup.find_all('script', src=re.compile(r'^https?://'))
            external_styles = soup.find_all('link', rel='stylesheet', href=re.compile(r'^https?://'))
            
            total_external = len(external_scripts) + len(external_styles)
            sri_protected = 0
            
            for script in external_scripts:
                if script.get('integrity'):
                    sri_protected += 1
                else:
                    results['resource_integrity'].append({
                        'type': 'script',
                        'url': script.get('src', '')[:100]
                    })
            
            for style in external_styles:
                if style.get('integrity'):
                    sri_protected += 1
                else:
                    results['resource_integrity'].append({
                        'type': 'stylesheet',
                        'url': style.get('href', '')[:100]
                    })
            
            if total_external > 0 and sri_protected < total_external:
                results['issues'].append(
                    f'Subresource Integrity missing: {total_external - sri_protected}/{total_external} resources unprotected'
                )
                results['security_impact'].append('Resources vulnerable to CDN compromise')
            
            # Check compression
            content_encoding = response.headers.get('Content-Encoding', '')
            if not content_encoding:
                results['issues'].append('No compression enabled (impacts performance and bandwidth)')
            
            # Check caching headers
            cache_headers = ['Cache-Control', 'ETag', 'Last-Modified']
            missing_cache = [h for h in cache_headers if h not in response.headers]
            if missing_cache:
                results['issues'].append(f'Missing cache headers: {", ".join(missing_cache)}')
            
            # Large resource detection
            page_size = len(response.content)
            results['page_size'] = page_size
            if page_size > 3000000:  # 3MB
                results['issues'].append(f'Large page size: {page_size / 1000000:.1f}MB (DDoS amplification risk)')
                results['security_impact'].append('Large page size increases DDoS amplification potential')
            
            # Check for resource hints
            dns_prefetch = soup.find_all('link', rel='dns-prefetch')
            preconnect = soup.find_all('link', rel='preconnect')
            
            results['performance_features'] = {
                'dns_prefetch': len(dns_prefetch),
                'preconnect': len(preconnect),
                'compression': content_encoding,
                'http2': response.raw.version == 20
            }
            
            # SEO Security checks
            seo_security = {}
            
            # Robots.txt check
            try:
                robots_response = self.session.get(f'{base_url}/robots.txt', timeout=5)
                if robots_response.status_code == 200:
                    robots_content = robots_response.text.lower()
                    if 'disallow: /admin' in robots_content or 'disallow: /private' in robots_content:
                        seo_security['robots_txt'] = 'Exposes sensitive paths'
                        results['issues'].append('robots.txt reveals sensitive directory structure')
            except:
                pass
            
            # Meta tags that might reveal information
            generator_meta = soup.find('meta', {'name': 'generator'})
            if generator_meta:
                seo_security['generator'] = generator_meta.get('content')
                results['security_impact'].append(f'CMS/Platform exposed via meta tag: {seo_security["generator"]}')
            
            results['seo_security'] = seo_security
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results