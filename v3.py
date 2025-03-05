import re
import socket
import smtplib
import dns.resolver
import logging
import time
import random
import requests
import tldextract
from typing import Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    email: str
    is_valid_format: bool = False
    has_mx_records: bool = False
    has_a_records: bool = False  # Added A record check
    is_deliverable: Optional[bool] = None
    is_disposable: bool = False
    is_role_account: bool = False
    score: float = 0.0  # 0-1 confidence score
    provider: Optional[str] = None
    reason: Optional[str] = None
    verification_method: str = "unknown"

class EnhancedEmailValidator:
    def __init__(self):
        # Regular expression for basic email format validation
        self.email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        # More permissive regex for international domains
        self.permissive_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
        
        # Cache for DNS records to avoid repeated lookups
        self.dns_cache: Dict[str, Dict[str, List[str]]] = {}
        
        # Cache for validation results
        self.validation_cache: Dict[str, ValidationResult] = {}
        
        # Known major email providers that block SMTP verification
        self.major_providers = {
            'gmail.com': 'Google',
            'yahoo.com': 'Yahoo',
            'outlook.com': 'Microsoft',
            'hotmail.com': 'Microsoft',
            'live.com': 'Microsoft',
            'msn.com': 'Microsoft',
            'aol.com': 'AOL',
            'icloud.com': 'Apple',
            'me.com': 'Apple',
            'mail.com': 'Mail.com',
            'protonmail.com': 'ProtonMail',
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
            'marocnet.net.ma': 'MarocNet',  # Added specifically for your example
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
        self.max_smtp_retries = 2
        
        # Timeout values
        self.dns_timeout = 5  # seconds
        self.smtp_timeout = 10  # seconds
        
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
    
    def validate_format(self, email: str, permissive: bool = False) -> bool:
        """
        Check if the email has a valid format using regex.
        
        Args:
            email: The email to validate
            permissive: Whether to use a more permissive regex for international domains
        """
        if permissive:
            return bool(re.match(self.permissive_regex, email))
        return bool(re.match(self.email_regex, email))
    
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
                   sender_email: str = "verify@example.com") -> Tuple[bool, Optional[str]]:
        """
        Verify email existence by connecting to the SMTP server.
        Returns a tuple of (is_deliverable, reason)
        
        This method includes multiple retries and better error handling for custom domains.
        """
        if not mx_servers:
            return False, "No MX records found"
        
        # Extract domain for custom handling
        domain = email.split('@')[1]
        
        # For some regional providers, we might need to use different sender addresses
        if any(regional in domain for regional in self.regional_providers):
            # Try with a sender from the same domain
            alt_sender = f"verify@{domain}"
            sender_emails = [sender_email, alt_sender]
        else:
            sender_emails = [sender_email]
        
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
    
    def verify_custom_domain(self, email: str, domain: str) -> Tuple[bool, float, str, str]:
        """
        Special verification for custom domains using multiple methods.
        Returns (is_deliverable, confidence_score, reason, method_used)
        """
        # Get both MX and A records
        mx_records = self.get_dns_records(domain, 'MX')
        a_records = self.get_dns_records(domain, 'A')
        
        # If no MX records but has A records, the A record might be handling mail
        if not mx_records and a_records:
            # Try SMTP verification with the A record as mail server
            is_deliverable, reason = self.verify_smtp(email, a_records)
            if is_deliverable:
                return True, 0.8, reason, "A-record SMTP"
            else:
                # For custom domains with A records but failed SMTP, we'll be more lenient
                # Many custom domains have valid emails but block SMTP verification
                return True, 0.6, "Domain exists but SMTP verification failed", "A-record existence"
        
        # If has MX records, try standard SMTP verification
        if mx_records:
            is_deliverable, reason = self.verify_smtp(email, mx_records)
            if is_deliverable:
                return True, 0.9, reason, "MX-record SMTP"
            else:
                # For custom domains with MX records but failed SMTP, we'll be more lenient
                return True, 0.7, "Domain has mail servers but SMTP verification failed", "MX-record existence"
        
        # If no MX or A records, the domain likely doesn't handle email
        return False, 0.2, "Domain has no mail servers", "DNS check"
    
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
    
    def validate_email(self, email: str, check_deliverability: bool = True) -> ValidationResult:
        """
        Validate an email address with multiple checks.
        
        Args:
            email: The email address to validate
            check_deliverability: Whether to check if the email can receive messages
            
        Returns:
            ValidationResult object with validation results
        """
        # Check cache first
        if email in self.validation_cache:
            return self.validation_cache[email]
        
        # Initialize result
        result = ValidationResult(email=email)
        
        # Step 1: Check email format (try both standard and permissive)
        standard_format = self.validate_format(email, permissive=False)
        permissive_format = self.validate_format(email, permissive=True)
        
        if not permissive_format:
            result.reason = "Invalid email format"
            self.validation_cache[email] = result
            return result
        
        result.is_valid_format = True
        # If it passes standard format, higher score
        result.score = 0.4 if standard_format else 0.3
        
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
        
        # Step 3: Check if it's a known provider
        is_major = domain in self.major_providers
        is_regional = domain in self.regional_providers
        
        if is_major:
            result.provider = self.major_providers[domain]
        elif is_regional:
            result.provider = self.regional_providers[domain]
        
        # Apply provider-specific rules
        likely_valid, provider_score, provider_reason = self.check_provider_rules(domain, local_part)
        result.score = max(result.score, provider_score)
        
        if not likely_valid:
            result.reason = provider_reason
            result.is_deliverable = False
            result.verification_method = "provider rules"
            self.validation_cache[email] = result
            return result
        
        # Step 4: Check deliverability if requested
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
            
            # For custom domains, use our enhanced custom domain verification
            else:
                is_deliverable, custom_score, reason, method = self.verify_custom_domain(email, domain)
                result.is_deliverable = is_deliverable
                result.reason = reason
                result.score = max(result.score, custom_score)
                result.verification_method = method
        
        # Ensure score is between 0 and 1
        result.score = max(0.0, min(1.0, result.score))
        
        # Cache the result
        self.validation_cache[email] = result
        return result
    
    def batch_validate(self, emails: List[str], check_deliverability: bool = True, 
                      max_workers: int = 5) -> Dict[str, ValidationResult]:
        """
        Validate multiple email addresses in parallel.
        
        Args:
            emails: List of email addresses to validate
            check_deliverability: Whether to check deliverability
            max_workers: Maximum number of parallel workers
        """
        results = {}
        
        # For small batches, don't use parallelism
        if len(emails) <= 3:
            for email in emails:
                results[email] = self.validate_email(email, check_deliverability)
                # Add a small delay between checks
                time.sleep(random.uniform(0.1, 0.5))
            return results
        
        # For larger batches, use parallel processing
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_email = {
                executor.submit(self.validate_email, email, check_deliverability): email 
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
    validator = EnhancedEmailValidator()
    
    # Test a single email
    email_to_test = input("Enter an email to validate: ")
    result = validator.validate_email(email_to_test)
    
    print("\nValidation Results:")
    print(f"Email: {result.email}")
    print(f"Valid Format: {result.is_valid_format}")
    print(f"Has MX Records: {result.has_mx_records}")
    print(f"Has A Records: {result.has_a_records}")
    print(f"Is Deliverable: {result.is_deliverable}")
    print(f"Provider: {result.provider or 'Unknown/Custom'}")
    print(f"Is Disposable: {result.is_disposable}")
    print(f"Is Role Account: {result.is_role_account}")
    print(f"Confidence Score: {result.score:.2f}")
    print(f"Verification Method: {result.verification_method}")
    
    if result.reason:
        print(f"Reason: {result.reason}")
    
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
        valid_mark = "✓" if res.score > 0.5 else "✗"
        print(f"\n{email}: {valid_mark} (Score: {res.score:.2f})")
        if res.provider:
            print(f"  Provider: {res.provider}")
        print(f"  Method: {res.verification_method}")
        if res.reason:
            print(f"  Reason: {res.reason}")