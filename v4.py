import re
import socket
import smtplib
import dns.resolver
import logging
import time
import random
import requests
import tldextract
import whois
import datetime
from typing import Dict, List, Optional, Set, Tuple, Union, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
from email.utils import parseaddr

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    email: str
    is_valid_format: bool = False
    has_mx_records: bool = False
    has_a_records: bool = False
    is_deliverable: Optional[bool] = None
    is_disposable: bool = False
    is_role_account: bool = False
    is_catch_all: Optional[bool] = None
    domain_age_days: Optional[int] = None
    score: float = 0.0  # 0-1 confidence score
    provider: Optional[str] = None
    reason: Optional[str] = None
    verification_method: str = "unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for easy serialization"""
        return {
            "email": self.email,
            "is_valid": self.score >= 0.75,  # Higher threshold for validity
            "score": round(self.score, 2),
            "provider": self.provider or "Custom Domain",
            "method": self.verification_method,
            "reason": self.reason or "Valid email address",
            "details": {
                "is_valid_format": self.is_valid_format,
                "has_mx_records": self.has_mx_records,
                "has_a_records": self.has_a_records,
                "is_deliverable": self.is_deliverable,
                "is_disposable": self.is_disposable,
                "is_role_account": self.is_role_account,
                "is_catch_all": self.is_catch_all,
                "domain_age_days": self.domain_age_days
            }
        }

class EnterpriseEmailValidator:
    def __init__(self):
        # Regular expression for strict email format validation (RFC 5322 compliant)
        self.strict_regex = r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        
        # More permissive regex for international domains
        self.permissive_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
        
        # Cache for DNS records to avoid repeated lookups
        self.dns_cache: Dict[str, Dict[str, List[str]]] = {}
        
        # Cache for validation results
        self.validation_cache: Dict[str, ValidationResult] = {}
        
        # Cache for catch-all detection
        self.catch_all_cache: Dict[str, bool] = {}
        
        # Cache for domain age
        self.domain_age_cache: Dict[str, Optional[int]] = {}
        
        # Known major email providers that block SMTP verification
        self.major_providers = {
            'gmail.com': 'Google',
            'googlemail.com': 'Google',
            'yahoo.com': 'Yahoo',
            'yahoo.co.uk': 'Yahoo',
            'yahoo.fr': 'Yahoo',
            'yahoo.co.jp': 'Yahoo',
            'outlook.com': 'Microsoft',
            'hotmail.com': 'Microsoft',
            'live.com': 'Microsoft',
            'msn.com': 'Microsoft',
            'aol.com': 'AOL',
            'icloud.com': 'Apple',
            'me.com': 'Apple',
            'mail.com': 'Mail.com',
            'protonmail.com': 'ProtonMail',
            'proton.me': 'ProtonMail',
            'zoho.com': 'Zoho',
            'yandex.com': 'Yandex',
            'gmx.com': 'GMX',
            'gmx.net': 'GMX',
        }
        
        # Regional email providers that might need special handling
        self.regional_providers = {
            'mail.ru': 'Mail.ru',
            'seznam.cz': 'Seznam',
            'wp.pl': 'Wirtualna Polska',
            'o2.pl': 'O2',
            'interia.pl': 'Interia',
            'rediffmail.com': 'Rediff',
            'sina.com': 'Sina',
            '163.com': 'NetEase',
            'qq.com': 'Tencent QQ',
            'naver.com': 'Naver',
            'daum.net': 'Daum',
            'web.de': 'Web.de',
            't-online.de': 'T-Online',
            'libero.it': 'Libero',
            'orange.fr': 'Orange',
            'wanadoo.fr': 'Wanadoo',
            'free.fr': 'Free',
            'laposte.net': 'La Poste',
            'sfr.fr': 'SFR',
            'ukr.net': 'UKR.net',
            'rambler.ru': 'Rambler',
            'yandex.ru': 'Yandex',
            'telenet.be': 'Telenet',
            'skynet.be': 'Skynet',
            'shaw.ca': 'Shaw',
            'rogers.com': 'Rogers',
            'sympatico.ca': 'Sympatico',
            'rr.com': 'Roadrunner',
            'optusnet.com.au': 'Optus',
            'bigpond.com': 'Bigpond',
            'marocnet.net.ma': 'MarocNet',
            'menara.ma': 'Menara',
            'iam.net.ma': 'IAM',
        }
        
        # Known corporate domains that should be treated with higher scrutiny
        self.corporate_domains = {
            'valeo.com': 'Valeo',
            'tateandlyle.com': 'Tate & Lyle',
            'lydec.co.ma': 'Lydec',
            'usmba.ac.ma': 'USMBA',
            'avanzit.ma': 'Avanzit',
        }
        
        # Common disposable email domains
        self.disposable_domains: Set[str] = self._load_disposable_domains()
        
        # Common role-based email prefixes
        self.role_prefixes = {
            'admin', 'info', 'support', 'sales', 'contact', 'help',
            'webmaster', 'postmaster', 'hostmaster', 'abuse', 'noreply',
            'no-reply', 'team', 'marketing', 'billing', 'office', 'mail',
            'jobs', 'career', 'hr', 'service', 'enquiry', 'inquiry'
        }
        
        # Maximum retries for SMTP verification
        self.max_smtp_retries = 3
        
        # Timeout values
        self.dns_timeout = 5  # seconds
        self.smtp_timeout = 10  # seconds
        
        # Sender emails for SMTP verification
        self.sender_emails = [
            "verify@example.com",
            "check@example.org",
            "validate@example.net"
        ]
        
        # Random strings for catch-all detection
        self.random_prefixes = [
            f"nonexistent{random.randint(10000, 99999)}",
            f"invalid{random.randint(10000, 99999)}",
            f"test{random.randint(10000, 99999)}"
        ]
        
    def _load_disposable_domains(self) -> Set[str]:
        """Load a list of known disposable email domains."""
        try:
            # Try to fetch from a public list
            response = requests.get(
                "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf",
                timeout=5
            )
            if response.status_code == 200:
                return set(response.text.strip().split('\n'))
        except Exception as e:
            logger.warning(f"Could not load disposable domains list: {e}")
        
        # Fallback to a small built-in list
        return {
            'mailinator.com', 'guerrillamail.com', 'temp-mail.org', 'fakeinbox.com',
            'tempmail.com', '10minutemail.com', 'yopmail.com', 'throwawaymail.com',
            'sharklasers.com', 'getairmail.com', 'mailnesia.com', 'mailcatch.com',
            'dispostable.com', 'tempinbox.com', 'emailondeck.com', 'emailsendr.com',
            'tempmail.net', 'trashmail.com', 'maildrop.cc', 'getnada.com'
        }
    
    def validate_format(self, email: str, strict: bool = True) -> bool:
        """
        Check if the email has a valid format using regex.
        
        Args:
            email: The email to validate
            strict: Whether to use strict RFC 5322 compliant regex
        """
        # First, use parseaddr to handle edge cases
        _, addr = parseaddr(email)
        if not addr or addr != email:
            return False
            
        if strict:
            return bool(re.match(self.strict_regex, email))
        return bool(re.match(self.permissive_regex, email))
    
    def get_dns_records(self, domain: str, record_type: str = 'MX') -> List[str]:
        """
        Get DNS records for a domain with caching.
        
        Args:
            domain: The domain to check
            record_type: The DNS record type ('MX', 'A', etc.)
        """
        # Check cache first
        if domain in self.dns_cache and record_type in self.dns_cache[domain]:
            return self.dns_cache[domain][record_type]
        
        # Initialize domain in cache if not present
        if domain not in self.dns_cache:
            self.dns_cache[domain] = {}
        
        try:
            if record_type == 'MX':
                records = dns.resolver.resolve(domain, 'MX', lifetime=self.dns_timeout)
                results = [str(x.exchange).rstrip('.') for x in records]
                # Sort by priority (lowest first)
                results.sort()
            elif record_type == 'A':
                records = dns.resolver.resolve(domain, 'A', lifetime=self.dns_timeout)
                results = [str(x) for x in records]
            else:
                records = dns.resolver.resolve(domain, record_type, lifetime=self.dns_timeout)
                results = [str(x) for x in records]
                
            self.dns_cache[domain][record_type] = results
            return results
            
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            logger.warning(f"No {record_type} records found for domain {domain}: {e}")
            self.dns_cache[domain][record_type] = []
            return []
    
    def verify_smtp(self, email: str, mx_servers: List[str], 
                   sender_emails: Optional[List[str]] = None) -> Tuple[bool, Optional[str]]:
        """
        Verify email existence by connecting to the SMTP server.
        Returns a tuple of (is_deliverable, reason)
        
        This method includes multiple retries and better error handling for custom domains.
        """
        if not mx_servers:
            return False, "No MX records found"
        
        if sender_emails is None:
            sender_emails = self.sender_emails
        
        # Extract domain for custom handling
        domain = email.split('@')[1]
        
        # For some regional providers, we might need to use different sender addresses
        if any(regional in domain for regional in self.regional_providers):
            # Try with a sender from the same domain
            alt_sender = f"verify@{domain}"
            sender_emails = [alt_sender] + sender_emails
        
        # Try each MX server
        for mx in mx_servers:
            # Try multiple sender emails
            for sender in sender_emails:
                # Try multiple times (with backoff)
                for attempt in range(self.max_smtp_retries):
                    try:
                        with smtplib.SMTP(mx, timeout=self.smtp_timeout) as smtp:
                            smtp.ehlo()
                            # Try to use STARTTLS if available
                            if smtp.has_extn('STARTTLS'):
                                smtp.starttls()
                                smtp.ehlo()
                            
                            # Some servers require a sender address
                            smtp.mail(sender)
                            
                            # The key check - see if the recipient is accepted
                            code, message = smtp.rcpt(email)
                            
                            smtp.quit()
                            
                            # SMTP status codes:
                            # 250 = Success
                            # 550 = Mailbox unavailable
                            # 551, 552, 553, 450, 451, 452 = Various temporary issues
                            # 503, 550, 551, 553 = Various permanent failures
                            
                            if code == 250:
                                return True, None
                            elif code == 550:
                                return False, "Mailbox unavailable"
                            else:
                                message_str = message.decode('utf-8', errors='ignore')
                                # Continue to next attempt if this one gave a temporary error
                                if code in (450, 451, 452):
                                    # Add exponential backoff
                                    time.sleep(2 ** attempt)
                                    continue
                                return False, f"SMTP Error: {code} - {message_str}"
                        
                    except (socket.timeout, socket.error, smtplib.SMTPException) as e:
                        logger.debug(f"SMTP error with {mx} (attempt {attempt+1}): {str(e)}")
                        # Add exponential backoff
                        time.sleep(2 ** attempt)
                        # Continue to next attempt
        
        return False, "All MX servers rejected connection or verification"
    
    def detect_catch_all(self, domain: str, mx_servers: List[str]) -> bool:
        """
        Detect if a domain has a catch-all email configuration.
        A catch-all domain accepts all emails regardless of whether the mailbox exists.
        """
        # Check cache first
        if domain in self.catch_all_cache:
            return self.catch_all_cache[domain]
        
        # Skip check for major providers (they don't use catch-all)
        if domain in self.major_providers:
            self.catch_all_cache[domain] = False
            return False
        
        # Try with a random non-existent email
        for prefix in self.random_prefixes:
            test_email = f"{prefix}@{domain}"
            is_valid, _ = self.verify_smtp(test_email, mx_servers)
            
            if is_valid:
                # If a random email is accepted, it's likely a catch-all domain
                self.catch_all_cache[domain] = True
                return True
            
            # Add a small delay between checks
            time.sleep(1)
        
        # If none of the random emails were accepted, it's not a catch-all
        self.catch_all_cache[domain] = False
        return False
    
    def get_domain_age(self, domain: str) -> Optional[int]:
        """
        Get the age of a domain in days.
        Returns None if the information cannot be retrieved.
        """
        # Check cache first
        if domain in self.domain_age_cache:
            return self.domain_age_cache[domain]
        
        try:
            # Extract the root domain
            extracted = tldextract.extract(domain)
            root_domain = f"{extracted.domain}.{extracted.suffix}"
            
            # Get WHOIS information
            domain_info = whois.whois(root_domain)
            
            # Get creation date
            creation_date = domain_info.creation_date
            
            # Handle multiple creation dates (some WHOIS servers return a list)
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                # Calculate age in days
                age_days = (datetime.datetime.now() - creation_date).days
                self.domain_age_cache[domain] = age_days
                return age_days
            
        except Exception as e:
            logger.debug(f"Could not get domain age for {domain}: {e}")
        
        self.domain_age_cache[domain] = None
        return None
    
    def check_provider_rules(self, domain: str, local_part: str) -> Tuple[bool, float, str]:
        """
        Apply provider-specific validation rules.
        Returns (likely_valid, confidence_score, reason)
        """
        # Check major providers
        provider = self.major_providers.get(domain)
        if provider:
            # Basic checks for major providers
            if provider == "Google":  # Gmail
                # Gmail username rules: 6-30 chars, letters, numbers, dots
                if len(local_part) < 6 or len(local_part) > 30:
                    return False, 0.3, "Gmail username too short or too long"
                if not re.match(r'^[a-zA-Z0-9.]+$', local_part):
                    return False, 0.3, "Invalid characters in Gmail username"
                return True, 0.8, f"Valid {provider} format"
                
            elif provider == "Microsoft":  # Outlook, Hotmail, Live
                # Microsoft username rules: 1-64 chars, letters, numbers, dots, underscores, dashes
                if len(local_part) < 1 or len(local_part) > 64:
                    return False, 0.3, "Microsoft username too short or too long"
                if not re.match(r'^[a-zA-Z0-9._%+-]+$', local_part):
                    return False, 0.3, "Invalid characters in Microsoft username"
                return True, 0.8, f"Valid {provider} format"
                
            elif provider == "Yahoo":
                # Yahoo username rules: 4-32 chars, letters, numbers, underscores
                if len(local_part) < 4 or len(local_part) > 32:
                    return False, 0.3, "Yahoo username too short or too long"
                if not re.match(r'^[a-zA-Z0-9_]+$', local_part):
                    return False, 0.3, "Invalid characters in Yahoo username"
                return True, 0.8, f"Valid {provider} format"
            
            # For other major providers, we'll assume valid with medium confidence
            return True, 0.7, f"Valid {provider} format"
        
        # Check regional providers
        provider = self.regional_providers.get(domain)
        if provider:
            # For regional providers, we'll be more lenient
            if not re.match(r'^[a-zA-Z0-9._%+-]+$', local_part):
                return False, 0.3, f"Invalid characters in {provider} username"
            return True, 0.7, f"Valid {provider} format"
        
        # Check corporate domains
        provider = self.corporate_domains.get(domain)
        if provider:
            # For corporate domains, apply stricter validation
            # Corporate emails often follow patterns like firstname.lastname
            if not re.match(r'^[a-zA-Z0-9._%+-]+$', local_part):
                return False, 0.3, f"Invalid characters in {provider} username"
                
            # Check for common corporate email patterns
            has_dot = '.' in local_part
            has_underscore = '_' in local_part
            has_hyphen = '-' in local_part
            
            # Many corporate emails use firstname.lastname format
            if has_dot or has_underscore or has_hyphen:
                return True, 0.6, f"Valid {provider} format"
            
            # If it doesn't match common patterns, lower confidence
            return True, 0.4, f"Unusual format for {provider}"
        
        # For unknown providers, just check for reasonable length and characters
        if len(local_part) < 1 or len(local_part) > 64:
            return False, 0.3, "Username too short or too long"
        if not re.match(r'^[a-zA-Z0-9._%+-]+$', local_part):
            return False, 0.3, "Invalid characters in username"
        
        # Unknown provider with valid format gets medium confidence
        return True, 0.5, "Valid format for unknown provider"
    
    def is_disposable(self, domain: str) -> bool:
        """Check if the email domain is a known disposable email service."""
        # Extract the root domain for checking
        extracted = tldextract.extract(domain)
        root_domain = f"{extracted.domain}.{extracted.suffix}"
        
        return domain in self.disposable_domains or root_domain in self.disposable_domains
    
    def is_role_account(self, local_part: str) -> bool:
        """Check if the email is a role-based account rather than personal."""
        return local_part.lower() in self.role_prefixes
    
    def validate_email(self, email: str, check_deliverability: bool = True,
                      detect_catch_all: bool = True) -> ValidationResult:
        """
        Validate an email address with multiple checks.
        
        Args:
            email: The email address to validate
            check_deliverability: Whether to check if the email can receive messages
            detect_catch_all: Whether to check if the domain has catch-all configuration
            
        Returns:
            ValidationResult object with validation results
        """
        # Check cache first
        if email in self.validation_cache:
            return self.validation_cache[email]
        
        # Initialize result
        result = ValidationResult(email=email)
        
        # Step 1: Check email format (try both standard and permissive)
        strict_format = self.validate_format(email, strict=True)
        permissive_format = self.validate_format(email, strict=False)
        
        if not permissive_format:
            result.reason = "Invalid email format"
            self.validation_cache[email] = result
            return result
        
        result.is_valid_format = True
        # If it passes strict format, higher score
        result.score = 0.4 if strict_format else 0.3
        
        # Extract domain and local part
        try:
            local_part, domain = email.split('@')
        except ValueError:
            result.reason = "Invalid email format (missing @ symbol)"
            self.validation_cache[email] = result
            return result
        
        # Handle multi-level domains better using tldextract
        extracted = tldextract.extract(domain)
        if not extracted.suffix:
            result.reason = "Invalid domain (no valid TLD)"
            result.score = 0.1
            self.validation_cache[email] = result
            return result
        
        # Check if it's a role account
        result.is_role_account = self.is_role_account(local_part)
        if result.is_role_account:
            result.score -= 0.1  # Slightly reduce score for role accounts
        
        # Check if it's a disposable email
        result.is_disposable = self.is_disposable(domain)
        if result.is_disposable:
            result.score -= 0.2  # Reduce score for disposable emails
            result.reason = "Disposable email domain"
        
        # Step 2: Check DNS records
        mx_records = self.get_dns_records(domain, 'MX')
        a_records = self.get_dns_records(domain, 'A')
        
        result.has_mx_records = len(mx_records) > 0
        result.has_a_records = len(a_records) > 0
        
        if result.has_mx_records:
            result.score += 0.2  # Having MX records increases score
        elif result.has_a_records:
            result.score += 0.1  # Having only A records increases score less
        else:
            result.reason = "No mail servers found for domain"
            result.score = 0.1
            self.validation_cache[email] = result
            return result
        
        # Step 3: Check domain age
        domain_age = self.get_domain_age(domain)
        result.domain_age_days = domain_age
        
        if domain_age is not None:
            if domain_age > 365:  # Older than 1 year
                result.score += 0.1
            elif domain_age < 30:  # Newer than 1 month
                result.score -= 0.1
        
        # Step 4: Check if it's a known provider
        is_major = domain in self.major_providers
        is_regional = domain in self.regional_providers
        is_corporate = domain in self.corporate_domains
        
        if is_major:
            result.provider = self.major_providers[domain]
        elif is_regional:
            result.provider = self.regional_providers[domain]
        elif is_corporate:
            result.provider = self.corporate_domains[domain]
        
        # Apply provider-specific rules
        likely_valid, provider_score, provider_reason = self.check_provider_rules(domain, local_part)
        result.score = max(result.score, provider_score)
        
        if not likely_valid:
            result.reason = provider_reason
            result.is_deliverable = False
            result.verification_method = "provider rules"
            self.validation_cache[email] = result
            return result
        
        # Step 5: Check deliverability if requested
        if check_deliverability:
            # Add a small random delay to avoid rate limiting
            time.sleep(random.uniform(0.5, 2.0))
            
            # For major providers, skip SMTP verification
            if is_major:
                result.is_deliverable = True
                result.reason = f"Major provider ({result.provider}) - SMTP verification skipped"
                result.verification_method = "provider recognition"
            
            # For regional providers, use provider-specific handling if available
            elif is_regional:
                result.is_deliverable = True
                result.reason = f"Regional provider ({result.provider}) - Using relaxed validation"
                result.verification_method = "regional provider recognition"
                
                # Still try SMTP verification for some regional providers
                if domain in ["mail.ru", "yandex.ru", "seznam.cz"]:  # These often allow SMTP verification
                    is_deliverable, reason = self.verify_smtp(email, mx_records)
                    if is_deliverable:
                        result.score += 0.2
                        result.verification_method = "SMTP verification"
            
            # For corporate domains, apply stricter validation
            elif is_corporate:
                # For corporate domains, SMTP verification is crucial
                is_deliverable, reason = self.verify_smtp(email, mx_records)
                
                # Check for catch-all if requested
                if detect_catch_all and (is_deliverable or reason == "All MX servers rejected connection or verification"):
                    is_catch_all = self.detect_catch_all(domain, mx_records)
                    result.is_catch_all = is_catch_all
                    
                    if is_catch_all:
                        # If it's a catch-all domain, reduce confidence significantly
                        result.score -= 0.3
                        result.reason = f"Corporate domain ({result.provider}) with catch-all configuration"
                        result.verification_method = "catch-all detection"
                        result.is_deliverable = False  # Mark as not deliverable despite SMTP success
                    else:
                        result.is_deliverable = is_deliverable
                        result.reason = reason
                        result.verification_method = "SMTP verification"
                        
                        if is_deliverable:
                            result.score += 0.3
                        else:
                            result.score -= 0.3
                else:
                    result.is_deliverable = is_deliverable
                    result.reason = reason
                    result.verification_method = "SMTP verification"
                    
                    if is_deliverable:
                        result.score += 0.3
                    else:
                        result.score -= 0.3
            
            # For custom domains, use our enhanced custom domain verification
            else:
                # First, check if it's a catch-all domain
                if detect_catch_all:
                    is_catch_all = self.detect_catch_all(domain, mx_records)
                    result.is_catch_all = is_catch_all
                    
                    if is_catch_all:
                        # If it's a catch-all domain, reduce confidence
                        result.score -= 0.2
                        result.reason = "Domain has catch-all configuration"
                        result.verification_method = "catch-all detection"
                
                # Then, perform SMTP verification
                is_deliverable, reason = self.verify_smtp(email, mx_records)
                
                # If it's a catch-all domain and SMTP verification passed,
                # we can't trust the result as much
                if result.is_catch_all and is_deliverable:
                    result.is_deliverable = False
                    result.reason = "Domain accepts all emails (catch-all)"
                    result.verification_method = "catch-all detection"
                else:
                    result.is_deliverable = is_deliverable
                    result.reason = reason
                    result.verification_method = "SMTP verification"
                    
                    if is_deliverable:
                        result.score += 0.3
                    else:
                        result.score -= 0.3
        
        # Ensure score is between 0 and 1
        result.score = max(0.0, min(1.0, result.score))
        
        # Ensure score is between 0 and 1
        result.score = max(0.0, min(1.0, result.score))
        
        # Cache the result
        self.validation_cache[email] = result
        return result
    
    def batch_validate(self, emails: List[str], check_deliverability: bool = True,
                      detect_catch_all: bool = True, max_workers: int = 5) -> Dict[str, ValidationResult]:
        """
        Validate multiple email addresses in parallel.
        
        Args:
            emails: List of email addresses to validate
            check_deliverability: Whether to check deliverability
            detect_catch_all: Whether to check for catch-all domains
            max_workers: Maximum number of parallel workers
        """
        results = {}
        
        # For small batches, don't use parallelism
        if len(emails) <= 3:
            for email in emails:
                results[email] = self.validate_email(email, check_deliverability, detect_catch_all)
                # Add a small delay between checks
                time.sleep(random.uniform(0.1, 0.5))
            return results
        
        # For larger batches, use parallel processing
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_email = {
                executor.submit(self.validate_email, email, check_deliverability, detect_catch_all): email 
                for email in emails
            }
            
            # Collect results as they complete
            for future in future_to_email:
                email = future_to_email[future]
                try:
                    results[email] = future.result()
                except Exception as e:
                    logger.error(f"Error validating {email}: {e}")
                    # Create a failed result
                    result = ValidationResult(email=email)
                    result.reason = f"Validation error: {str(e)}"
                    results[email] = result
        
        return results
    
    def suggest_corrections(self, email: str) -> List[str]:
        """Suggest possible corrections for common typos in email addresses."""
        if '@' not in email:
            return []
            
        local_part, domain = email.split('@')
        suggestions = []
        
        # Common domain typos
        common_domains = {
            'gmail.com': ['gmail.co', 'gmail.org', 'gmial.com', 'gamil.com', 'gmal.com', 'gmai.com'],
            'yahoo.com': ['yahoo.co', 'yaho.com', 'yahooo.com', 'yaho.co'],
            'hotmail.com': ['hotmail.co', 'hotmial.com', 'hotmil.com', 'hotamail.com'],
            'outlook.com': ['outlook.co', 'outook.com', 'outlok.com'],
        }
        
        # Check for domain typos
        for correct_domain, typos in common_domains.items():
            if domain in typos:
                suggestions.append(f"{local_part}@{correct_domain}")
        
        # Check for TLD typos (.cm instead of .com, etc.)
        tld_fixes = {
            '.cm': '.com',
            '.co': '.com',
            '.or': '.org',
            '.ne': '.net',
        }
        
        for wrong_tld, correct_tld in tld_fixes.items():
            if domain.endswith(wrong_tld):
                fixed_domain = domain[:-len(wrong_tld)] + correct_tld
                suggestions.append(f"{local_part}@{fixed_domain}")
        
        return suggestions

# Example usage
if __name__ == "__main__":
    validator = EnterpriseEmailValidator()
    
    # Test a single email
    email_to_test = input("Enter an email to validate: ")
    result = validator.validate_email(email_to_test)
    
    print("\nValidation Results:")
    result_dict = result.to_dict()
    print(f"Email: {result_dict['email']}")
    print(f"Is Valid: {'✓' if result_dict['is_valid'] else '✗'} (Score: {result_dict['score']})")
    print(f"Provider: {result_dict['provider']}")
    print(f"Method: {result_dict['method']}")
    print(f"Reason: {result_dict['reason']}")
    
    if result.is_catch_all:
        print(f"Warning: Domain has catch-all configuration")
    
    # Check for possible corrections
    suggestions = validator.suggest_corrections(email_to_test)
    if suggestions:
        print("\nDid you mean:")
        for suggestion in suggestions:
            print(f"  - {suggestion}")
    
    # Batch validation example
    print("\nBatch Validation Example:")
    print("Enter multiple emails separated by commas:")
    batch_emails = input().split(',')
    batch_results = validator.batch_validate([email.strip() for email in batch_emails])
    
    for email, res in batch_results.items():
        result_dict = res.to_dict()
        valid_mark = "✓" if result_dict['is_valid'] else "✗"
        print(f"\n{email}: {valid_mark} (Score: {result_dict['score']})")
        print(f"  Provider: {result_dict['provider']}")
        print(f"  Method: {result_dict['method']}")
        print(f"  Reason: {result_dict['reason']}")
        
        if res.is_catch_all:
            print(f"  Warning: Domain has catch-all configuration")