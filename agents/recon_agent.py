import subprocess
import asyncio
import aiohttp
import json
import logging
import dns.resolver
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import shodan
import os
import re
from utils.helpers import get_env_var, safe_json_dumps, ProgressTracker
from utils.validators import is_valid_domain, resolve_domain_to_ip


class ReconAgent:
    """Reconnaissance Agent for gathering intelligence on domains and hosts."""

    def __init__(self):
        self.shodan_api_key = get_env_var('SHODAN_API_KEY')
        self.shodan_api = None
        if self.shodan_api_key:
            try:
                self.shodan_api = shodan.Shodan(self.shodan_api_key)
            except Exception as e:
                logging.warning(f"Failed to initialize Shodan API: {e}")

        self.results = {}
        self.executor = ThreadPoolExecutor(max_workers=5)

    async def perform_reconnaissance(self, target: str, session_id: str) -> Dict[str, Any]:
        """
        Perform comprehensive reconnaissance on a target domain.

        Args:
            target: Domain name to investigate
            session_id: Session identifier for tracking

        Returns:
            Dictionary containing all reconnaissance results
        """
        logging.info(f"Starting reconnaissance for target: {target}")

        self.results = {
            'target': target,
            'session_id': session_id,
            'timestamp': None,
            'subdomains': [],
            'dns_records': {},
            'emails': [],
            'shodan_data': {},
            'whois_info': {},
            'certificates': [],
            'technologies': [],
            'social_media': [],
            'metadata': {}
        }

        # Run reconnaissance tasks concurrently
        tasks = [
            self._subdomain_enumeration(target),
            self._dns_enumeration(target),
            self._email_harvesting(target),
            self._shodan_search(target),
            self._whois_lookup(target),
            self._certificate_transparency(target),
            self._technology_detection(target),
            self._social_media_discovery(target)
        ]

        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as e:
            logging.error(f"Error during reconnaissance: {e}")

        # Add metadata
        self.results['metadata'] = {
            'total_subdomains': len(self.results['subdomains']),
            'total_emails': len(self.results['emails']),
            'dns_record_types': list(self.results['dns_records'].keys()),
            'technologies_count': len(self.results['technologies'])
        }

        logging.info(f"Reconnaissance completed for {target}")
        return self.results

    async def _subdomain_enumeration(self, domain: str):
        """Enumerate subdomains using multiple techniques."""
        logging.info(f"Starting subdomain enumeration for {domain}")
        subdomains = set()

        try:
            # Use Amass for passive subdomain discovery
            amass_results = await self._run_amass(domain)
            subdomains.update(amass_results)

            # Use certificate transparency logs
            ct_results = await self._certificate_transparency_subdomains(domain)
            subdomains.update(ct_results)

            # DNS brute force common subdomains
            common_subs = await self._dns_bruteforce(domain)
            subdomains.update(common_subs)

            self.results['subdomains'] = list(subdomains)
            logging.info(f"Found {len(subdomains)} subdomains for {domain}")

        except Exception as e:
            logging.error(f"Error in subdomain enumeration: {e}")

    async def _run_amass(self, domain: str) -> List[str]:
        """Run Amass for subdomain discovery."""
        try:
            amass_path = get_env_var('AMASS_PATH', 'amass')
            cmd = [amass_path, 'enum', '-passive',
                   '-d', domain, '-timeout', '5']

            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=300)

            if result.returncode == 0:
                subdomains = []
                for line in stdout.decode().split('\n'):
                    line = line.strip()
                    if line and is_valid_domain(line):
                        subdomains.append(line)
                return subdomains
            else:
                logging.warning(f"Amass failed: {stderr.decode()}")
                return []

        except (FileNotFoundError, TimeoutError) as e:
            logging.warning(f"Amass not available or timed out: {e}")
            return []
        except Exception as e:
            logging.error(f"Error running Amass: {e}")
            return []

    async def _certificate_transparency_subdomains(self, domain: str) -> List[str]:
        """Query certificate transparency logs for subdomains."""
        subdomains = set()

        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://crt.sh/?q=%25.{domain}&output=json"

                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()

                        for cert in data:
                            name_value = cert.get('name_value', '')
                            for name in name_value.split('\n'):
                                name = name.strip()
                                if name and is_valid_domain(name) and domain in name:
                                    subdomains.add(name)

        except Exception as e:
            logging.warning(f"Error querying certificate transparency: {e}")

        return list(subdomains)

    async def _dns_bruteforce(self, domain: str) -> List[str]:
        """Brute force common subdomain names."""
        common_subdomains = [
            'www', 'mail', 'ftp', 'webmail', 'admin', 'test', 'dev', 'staging',
            'api', 'app', 'cdn', 'blog', 'shop', 'store', 'secure', 'vpn',
            'remote', 'portal', 'dashboard', 'panel', 'cpanel', 'phpmyadmin',
            'mysql', 'sql', 'db', 'database', 'backup', 'old', 'new', 'beta'
        ]

        found_subdomains = []

        async def check_subdomain(sub):
            subdomain = f"{sub}.{domain}"
            try:
                ip = resolve_domain_to_ip(subdomain)
                if ip:
                    found_subdomains.append(subdomain)
            except:
                pass

        # Run checks concurrently
        tasks = [check_subdomain(sub) for sub in common_subdomains]
        await asyncio.gather(*tasks, return_exceptions=True)

        return found_subdomains

    async def _dns_enumeration(self, domain: str):
        """Enumerate DNS records."""
        logging.info(f"Starting DNS enumeration for {domain}")
        dns_records = {}

        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR']

        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_records[record_type] = [str(answer) for answer in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception):
                dns_records[record_type] = []

        self.results['dns_records'] = dns_records
        logging.info(f"DNS enumeration completed for {domain}")

    async def _email_harvesting(self, domain: str):
        """Harvest email addresses using theHarvester."""
        logging.info(f"Starting email harvesting for {domain}")

        try:
            harvester_path = get_env_var('THEHARVESTER_PATH', 'theHarvester')
            sources = ['google', 'bing', 'yahoo', 'duckduckgo']

            emails = set()

            for source in sources:
                try:
                    cmd = [harvester_path, '-d', domain,
                           '-b', source, '-l', '100']

                    result = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )

                    stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=120)

                    if result.returncode == 0:
                        # Extract emails from output
                        email_pattern = re.compile(
                            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
                        found_emails = email_pattern.findall(stdout.decode())
                        emails.update(found_emails)

                except Exception as e:
                    logging.warning(f"Error with {source} source: {e}")
                    continue

            self.results['emails'] = list(emails)
            logging.info(f"Found {len(emails)} emails for {domain}")

        except Exception as e:
            logging.error(f"Error in email harvesting: {e}")

    async def _shodan_search(self, domain: str):
        """Search Shodan for information about the domain."""
        if not self.shodan_api:
            logging.warning("Shodan API not available")
            return

        logging.info(f"Starting Shodan search for {domain}")

        try:
            # Get IP address for domain
            ip = resolve_domain_to_ip(domain)
            if not ip:
                logging.warning(f"Could not resolve IP for {domain}")
                return

            # Search Shodan for the IP
            host_info = self.shodan_api.host(ip)

            self.results['shodan_data'] = {
                'ip': ip,
                'hostnames': host_info.get('hostnames', []),
                'ports': host_info.get('ports', []),
                'vulns': host_info.get('vulns', []),
                'os': host_info.get('os'),
                'org': host_info.get('org'),
                'isp': host_info.get('isp'),
                'country': host_info.get('country_name'),
                'city': host_info.get('city'),
                'last_update': host_info.get('last_update'),
                'services': []
            }

            # Extract service information
            for service in host_info.get('data', []):
                service_info = {
                    'port': service.get('port'),
                    'protocol': service.get('transport'),
                    'product': service.get('product'),
                    'version': service.get('version'),
                    # Truncate long banners
                    'banner': service.get('banner', '')[:500]
                }
                self.results['shodan_data']['services'].append(service_info)

            logging.info(f"Shodan search completed for {domain}")

        except Exception as e:
            logging.error(f"Error in Shodan search: {e}")

    async def _whois_lookup(self, domain: str):
        """Perform WHOIS lookup."""
        logging.info(f"Starting WHOIS lookup for {domain}")

        try:
            cmd = ['whois', domain]

            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=30)

            if result.returncode == 0:
                whois_text = stdout.decode()

                # Parse important WHOIS information
                self.results['whois_info'] = {
                    'raw': whois_text,
                    'registrar': self._extract_whois_field(whois_text, 'Registrar:'),
                    'creation_date': self._extract_whois_field(whois_text, 'Creation Date:'),
                    'expiration_date': self._extract_whois_field(whois_text, 'Registry Expiry Date:'),
                    'name_servers': self._extract_whois_field(whois_text, 'Name Server:', multiple=True)
                }

            logging.info(f"WHOIS lookup completed for {domain}")

        except Exception as e:
            logging.error(f"Error in WHOIS lookup: {e}")

    def _extract_whois_field(self, whois_text: str, field: str, multiple: bool = False) -> str:
        """Extract field from WHOIS text."""
        pattern = rf'{re.escape(field)}\s*(.+)'
        matches = re.findall(pattern, whois_text, re.IGNORECASE)

        if multiple:
            return [match.strip() for match in matches]
        elif matches:
            return matches[0].strip()
        else:
            return ""

    async def _certificate_transparency(self, domain: str):
        """Query certificate transparency logs."""
        logging.info(f"Starting certificate transparency search for {domain}")

        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://crt.sh/?q={domain}&output=json"

                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        certs = await response.json()

                        cert_info = []
                        for cert in certs[:10]:  # Limit to first 10 certificates
                            cert_data = {
                                'id': cert.get('id'),
                                'issuer': cert.get('issuer_name'),
                                'common_name': cert.get('common_name'),
                                'not_before': cert.get('not_before'),
                                'not_after': cert.get('not_after'),
                                'serial_number': cert.get('serial_number')
                            }
                            cert_info.append(cert_data)

                        self.results['certificates'] = cert_info

        except Exception as e:
            logging.error(f"Error in certificate transparency search: {e}")

    async def _technology_detection(self, domain: str):
        """Detect technologies used by the website."""
        logging.info(f"Starting technology detection for {domain}")

        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://{domain}"

                try:
                    async with session.get(url, timeout=10) as response:
                        await self._analyze_http_response(response)
                except:
                    pass

                # Try HTTPS
                url = f"https://{domain}"
                try:
                    async with session.get(url, timeout=10) as response:
                        await self._analyze_http_response(response)
                except:
                    pass

        except Exception as e:
            logging.error(f"Error in technology detection: {e}")

    async def _analyze_http_response(self, response):
        """Analyze HTTP response for technology indicators."""
        headers = response.headers
        content = await response.text()

        technologies = []

        # Check server header
        server = headers.get('Server', '')
        if server:
            technologies.append({'type': 'Server', 'name': server})

        # Check X-Powered-By header
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            technologies.append({'type': 'Framework', 'name': powered_by})

        # Check for common technologies in content
        tech_patterns = {
            'WordPress': r'wp-content|wp-includes|wordpress',
            'Drupal': r'drupal|sites/default',
            'Joomla': r'joomla|com_content',
            'jQuery': r'jquery',
            'Bootstrap': r'bootstrap',
            'Angular': r'angular|ng-',
            'React': r'react|jsx',
            'Vue.js': r'vue\.js|v-'
        }

        for tech, pattern in tech_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                technologies.append({'type': 'Technology', 'name': tech})

        self.results['technologies'].extend(technologies)

    async def _social_media_discovery(self, domain: str):
        """Discover social media accounts associated with the domain."""
        logging.info(f"Starting social media discovery for {domain}")

        # Extract company name from domain
        company_name = domain.split('.')[0]

        social_platforms = [
            ('Twitter', f'https://twitter.com/{company_name}'),
            ('Facebook', f'https://facebook.com/{company_name}'),
            ('LinkedIn', f'https://linkedin.com/company/{company_name}'),
            ('Instagram', f'https://instagram.com/{company_name}'),
            ('YouTube', f'https://youtube.com/c/{company_name}')
        ]

        found_accounts = []

        try:
            async with aiohttp.ClientSession() as session:
                for platform, url in social_platforms:
                    try:
                        async with session.get(url, timeout=10) as response:
                            if response.status == 200:
                                found_accounts.append({
                                    'platform': platform,
                                    'url': url,
                                    'status': 'Found'
                                })
                    except:
                        pass

            self.results['social_media'] = found_accounts

        except Exception as e:
            logging.error(f"Error in social media discovery: {e}")

    def generate_report(self) -> str:
        """Generate a comprehensive reconnaissance report."""
        return safe_json_dumps(self.results, indent=2)
