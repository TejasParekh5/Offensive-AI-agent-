"""
Flask Recon Agent - OSINT and Reconnaissance Module
Performs domain reconnaissance using various security tools.
"""

import subprocess
import asyncio
import json
import logging
import requests
import dns.resolver
import ssl
import socket
from datetime import datetime
from typing import Dict, List, Optional, Any
import os
import tempfile
import threading
import time

class FlaskReconAgent:
    """Flask-compatible reconnaissance agent for domain intelligence gathering."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.shodan_api_key = os.environ.get('SHODAN_API_KEY')
        self.results = {}
        
    def perform_reconnaissance(self, target: str, session_id: str) -> Dict[str, Any]:
        """
        Perform comprehensive reconnaissance on a domain target.
        
        Args:
            target: Domain name to investigate
            session_id: Assessment session identifier
            
        Returns:
            Dictionary containing all reconnaissance results
        """
        self.logger.info(f"Starting reconnaissance for {target}")
        
        recon_results = {
            'target': target,
            'session_id': session_id,
            'timestamp': datetime.now().isoformat(),
            'subdomains': [],
            'dns_records': {},
            'shodan_results': {},
            'certificates': {},
            'emails': [],
            'technologies': [],
            'whois_info': {},
            'social_media': [],
            'errors': []
        }
        
        # Run reconnaissance modules
        try:
            # DNS enumeration
            recon_results['dns_records'] = self._perform_dns_enumeration(target)
            
            # Subdomain discovery
            recon_results['subdomains'] = self._discover_subdomains(target)
            
            # Shodan intelligence (if API key available)
            if self.shodan_api_key:
                recon_results['shodan_results'] = self._query_shodan(target)
            
            # Certificate transparency
            recon_results['certificates'] = self._check_certificates(target)
            
            # Email harvesting
            recon_results['emails'] = self._harvest_emails(target)
            
            # Technology detection
            recon_results['technologies'] = self._detect_technologies(target)
            
            # WHOIS information
            recon_results['whois_info'] = self._get_whois_info(target)
            
            # Social media presence
            recon_results['social_media'] = self._check_social_media(target)
            
        except Exception as e:
            self.logger.error(f"Reconnaissance error: {e}")
            recon_results['errors'].append(str(e))
        
        self.logger.info(f"Reconnaissance completed for {target}")
        return recon_results
    
    def _perform_dns_enumeration(self, target: str) -> Dict[str, List[str]]:
        """Perform DNS record enumeration."""
        dns_records = {
            'A': [],
            'AAAA': [],
            'MX': [],
            'NS': [],
            'TXT': [],
            'CNAME': [],
            'SOA': []
        }
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(target, record_type)
                for rdata in answers:
                    dns_records[record_type].append(str(rdata))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception):
                continue
        
        self.logger.info(f"DNS enumeration completed for {target}")
        return dns_records
    
    def _discover_subdomains(self, target: str) -> List[Dict[str, Any]]:
        """Discover subdomains using multiple techniques."""
        subdomains = []
        
        # Method 1: Common subdomain wordlist
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging',
            'api', 'blog', 'shop', 'portal', 'support', 'help',
            'secure', 'login', 'vpn', 'remote', 'cloud', 'app'
        ]
        
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{target}"
            if self._check_domain_exists(full_domain):
                subdomain_info = {
                    'domain': full_domain,
                    'method': 'wordlist',
                    'ip_addresses': self._resolve_domain(full_domain),
                    'discovered_at': datetime.now().isoformat()
                }
                subdomains.append(subdomain_info)
        
        # Method 2: Certificate Transparency logs
        ct_subdomains = self._query_certificate_transparency(target)
        for subdomain in ct_subdomains:
            if not any(s['domain'] == subdomain for s in subdomains):
                subdomain_info = {
                    'domain': subdomain,
                    'method': 'certificate_transparency',
                    'ip_addresses': self._resolve_domain(subdomain),
                    'discovered_at': datetime.now().isoformat()
                }
                subdomains.append(subdomain_info)
        
        # Method 3: theHarvester (if available)
        harvester_subdomains = self._run_theharvester(target)
        for subdomain in harvester_subdomains:
            if not any(s['domain'] == subdomain for s in subdomains):
                subdomain_info = {
                    'domain': subdomain,
                    'method': 'theharvester',
                    'ip_addresses': self._resolve_domain(subdomain),
                    'discovered_at': datetime.now().isoformat()
                }
                subdomains.append(subdomain_info)
        
        # Method 4: Amass (if available)
        amass_subdomains = self._run_amass(target)
        for subdomain in amass_subdomains:
            if not any(s['domain'] == subdomain for s in subdomains):
                subdomain_info = {
                    'domain': subdomain,
                    'method': 'amass',
                    'ip_addresses': self._resolve_domain(subdomain),
                    'discovered_at': datetime.now().isoformat()
                }
                subdomains.append(subdomain_info)
        
        self.logger.info(f"Found {len(subdomains)} subdomains for {target}")
        return subdomains
    
    def _check_domain_exists(self, domain: str) -> bool:
        """Check if a domain exists by resolving it."""
        try:
            dns.resolver.resolve(domain, 'A')
            return True
        except:
            return False
    
    def _resolve_domain(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses."""
        ip_addresses = []
        try:
            answers = dns.resolver.resolve(domain, 'A')
            ip_addresses = [str(rdata) for rdata in answers]
        except:
            pass
        return ip_addresses
    
    def _query_certificate_transparency(self, target: str) -> List[str]:
        """Query Certificate Transparency logs for subdomains."""
        subdomains = []
        try:
            # Use crt.sh API
            url = f"https://crt.sh/?q=%.{target}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                certificates = response.json()
                for cert in certificates:
                    name_value = cert.get('name_value', '')
                    for domain in name_value.split('\n'):
                        domain = domain.strip()
                        if domain and domain.endswith(target) and domain not in subdomains:
                            subdomains.append(domain)
        except Exception as e:
            self.logger.error(f"Certificate transparency query error: {e}")
        
        return subdomains[:50]  # Limit results
    
    def _run_theharvester(self, target: str) -> List[str]:
        """Run theHarvester for subdomain discovery."""
        subdomains = []
        try:
            # Check if theHarvester is available
            cmd = ['theHarvester', '-d', target, '-b', 'all', '-f', 'temp_harvester']
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=60,
                cwd=tempfile.gettempdir()
            )
            
            if result.returncode == 0:
                # Parse output for subdomains
                for line in result.stdout.split('\n'):
                    if target in line and line.strip().endswith(target):
                        domain = line.strip()
                        if domain not in subdomains:
                            subdomains.append(domain)
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.logger.debug(f"theHarvester not available or failed: {e}")
        
        return subdomains[:20]  # Limit results
    
    def _run_amass(self, target: str) -> List[str]:
        """Run Amass for subdomain discovery."""
        subdomains = []
        try:
            cmd = ['amass', 'enum', '-d', target, '-timeout', '2']
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=120
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    domain = line.strip()
                    if domain and domain.endswith(target):
                        subdomains.append(domain)
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.logger.debug(f"Amass not available or failed: {e}")
        
        return subdomains[:30]  # Limit results
    
    def _query_shodan(self, target: str) -> Dict[str, Any]:
        """Query Shodan for target intelligence."""
        if not self.shodan_api_key:
            return {}
        
        try:
            import shodan
            api = shodan.Shodan(self.shodan_api_key)
            
            # Search for the target
            results = api.search(f"hostname:{target}")
            
            shodan_data = {
                'total_results': results.get('total', 0),
                'hosts': [],
                'facets': results.get('facets', {}),
                'query_credits_used': 1
            }
            
            # Process host results
            for result in results.get('matches', [])[:10]:  # Limit to 10 results
                host_info = {
                    'ip': result.get('ip_str'),
                    'port': result.get('port'),
                    'organization': result.get('org'),
                    'location': {
                        'country': result.get('location', {}).get('country_name'),
                        'city': result.get('location', {}).get('city'),
                        'coordinates': [
                            result.get('location', {}).get('latitude'),
                            result.get('location', {}).get('longitude')
                        ]
                    },
                    'banners': result.get('data', ''),
                    'vulns': list(result.get('vulns', [])),
                    'timestamp': result.get('timestamp')
                }
                shodan_data['hosts'].append(host_info)
            
            self.logger.info(f"Shodan query completed for {target}")
            return shodan_data
            
        except Exception as e:
            self.logger.error(f"Shodan query error: {e}")
            return {'error': str(e)}
    
    def _check_certificates(self, target: str) -> Dict[str, Any]:
        """Check SSL/TLS certificates."""
        cert_info = {}
        
        try:
            # Get certificate information
            context = ssl.create_default_context()
            
            with socket.create_connection((target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    cert_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'signature_algorithm': cert.get('signatureAlgorithm'),
                        'extensions': []
                    }
                    
                    # Extract Subject Alternative Names
                    for ext in cert.get('subjectAltName', []):
                        if ext[0] == 'DNS':
                            cert_info['extensions'].append({
                                'type': 'Subject Alternative Name',
                                'value': ext[1]
                            })
        
        except Exception as e:
            self.logger.debug(f"Certificate check failed for {target}: {e}")
            cert_info = {'error': str(e)}
        
        return cert_info
    
    def _harvest_emails(self, target: str) -> List[Dict[str, str]]:
        """Harvest email addresses related to the target."""
        emails = []
        
        try:
            # Method 1: Search engines (simplified)
            search_queries = [
                f'site:{target} "@{target}"',
                f'"{target}" email contact'
            ]
            
            # Method 2: Common email patterns
            common_emails = [
                f'admin@{target}',
                f'info@{target}',
                f'contact@{target}',
                f'support@{target}',
                f'webmaster@{target}',
                f'sales@{target}',
                f'security@{target}'
            ]
            
            for email in common_emails:
                # Simple validation check
                if '@' in email and '.' in email:
                    emails.append({
                        'email': email,
                        'source': 'common_patterns',
                        'confidence': 'low'
                    })
        
        except Exception as e:
            self.logger.error(f"Email harvesting error: {e}")
        
        return emails[:20]  # Limit results
    
    def _detect_technologies(self, target: str) -> List[Dict[str, Any]]:
        """Detect technologies used by the target website."""
        technologies = []
        
        try:
            # Make HTTP request to analyze headers and content
            url = f"http://{target}"
            response = requests.get(url, timeout=10, allow_redirects=True)
            
            # Analyze headers
            headers = response.headers
            
            # Server detection
            server = headers.get('Server', '')
            if server:
                technologies.append({
                    'name': server,
                    'category': 'Web Server',
                    'confidence': 'high',
                    'source': 'http_header'
                })
            
            # Framework detection
            x_powered_by = headers.get('X-Powered-By', '')
            if x_powered_by:
                technologies.append({
                    'name': x_powered_by,
                    'category': 'Framework',
                    'confidence': 'high',
                    'source': 'http_header'
                })
            
            # Content analysis (simplified)
            content = response.text.lower()
            
            # Common technology indicators
            tech_indicators = {
                'wordpress': ['wp-content', 'wp-includes'],
                'drupal': ['drupal', 'sites/default'],
                'joomla': ['joomla', 'components/com_'],
                'react': ['react', '__reactinternalinstance'],
                'angular': ['angular', 'ng-app'],
                'vue.js': ['vue.js', 'vue.min.js'],
                'jquery': ['jquery', 'jquery.min.js'],
                'bootstrap': ['bootstrap', 'bootstrap.min.css']
            }
            
            for tech, indicators in tech_indicators.items():
                for indicator in indicators:
                    if indicator in content:
                        technologies.append({
                            'name': tech,
                            'category': 'CMS/Framework',
                            'confidence': 'medium',
                            'source': 'content_analysis'
                        })
                        break
        
        except Exception as e:
            self.logger.debug(f"Technology detection error: {e}")
        
        return technologies
    
    def _get_whois_info(self, target: str) -> Dict[str, Any]:
        """Get WHOIS information for the domain."""
        whois_info = {}
        
        try:
            # Try using whois command if available
            result = subprocess.run(
                ['whois', target],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                whois_text = result.stdout
                
                # Parse key information
                lines = whois_text.split('\n')
                for line in lines:
                    line = line.strip()
                    if ':' in line:
                        key, value = line.split(':', 1)
                        key = key.strip().lower()
                        value = value.strip()
                        
                        if key in ['registrar', 'creation date', 'expiry date', 'updated date']:
                            whois_info[key] = value
        
        except Exception as e:
            self.logger.debug(f"WHOIS query error: {e}")
            whois_info = {'error': 'WHOIS data not available'}
        
        return whois_info
    
    def _check_social_media(self, target: str) -> List[Dict[str, str]]:
        """Check for social media presence."""
        social_accounts = []
        
        # Common social media platforms
        platforms = {
            'twitter': f'https://twitter.com/{target.split(".")[0]}',
            'facebook': f'https://facebook.com/{target.split(".")[0]}',
            'linkedin': f'https://linkedin.com/company/{target.split(".")[0]}',
            'instagram': f'https://instagram.com/{target.split(".")[0]}',
            'youtube': f'https://youtube.com/c/{target.split(".")[0]}'
        }
        
        for platform, url in platforms.items():
            try:
                response = requests.head(url, timeout=5, allow_redirects=True)
                if response.status_code == 200:
                    social_accounts.append({
                        'platform': platform,
                        'url': url,
                        'status': 'found',
                        'confidence': 'low'  # Needs manual verification
                    })
            except:
                continue
        
        return social_accounts
