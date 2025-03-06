import re
import socket
import smtplib
import dns.resolver
import logging
import time
import random
import requests
import tldextract
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
    score: float = 0.0  # 0-1 confidence score
    provider: Optional[str] = None
    reason: Optional[str] = None
    verification_method: str = "unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for easy serialization"""
        return {
            "email": self.email,
            "is_valid": self.score >= 0.6,  # Lower threshold based on pattern analysis
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
                "is_catch_all": self.is_catch_all
            }
        }

class SmartEmailValidator:
    def __init__(self):
        # Regular expression for email format validation
        self.email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        # Cache for DNS records to avoid repeated lookups
        self.dns_cache: Dict[str, Dict[str, List[str]]] = {}
        
        # Cache for validation results
        self.validation_cache: Dict[str, ValidationResult] = {}
        
        # Known major email providers
        self.major_providers = {
            'gmail.com': 'Google',
            'googlemail.com': 'Google',
            'yahoo.com': 'Yahoo',
            'yahoo.co.uk': 'Yahoo',
            'yahoo.fr': 'Yahoo',
            'outlook.com': 'Microsoft',
            'hotmail.com': 'Microsoft',
            'live.com': 'Microsoft',
            'msn.com': 'Microsoft',
            'aol.com': 'AOL',
            'icloud.com': 'Apple',
            'me.com': 'Apple',
            'protonmail.com': 'ProtonMail',
            'proton.me': 'ProtonMail',
            'zoho.com': 'Zoho',
        }
        
        # Regional providers that need special handling
        self.regional_providers = {
            'menara.ma': 'Menara',
            'marocnet.net.ma': 'MarocNet',
            'iam.net.ma': 'IAM',
            'wanadoo.fr': 'Wanadoo',
            'wanadoopro.ma': 'Wanadoo',
            'mail.ru': 'Mail.ru',
            'yandex.ru': 'Yandex',
        }
        
        # Domains that are known to give false negatives with SMTP checks
        # These domains often return "Mailbox unavailable" for valid emails
        self.lenient_domains = {
            'lydec.co.ma': 'Lydec',
            'avanzit.ma': 'Avanzit',
            'ma.nestle.com': 'Nestle',
            'jacobs-esa.com': 'Jacobs',
            'newrest.eu': 'Newrest',
            'sopriam-ona.com': 'Sopriam',
            'snep.ma': 'SNEP',
            'total.co.ma': 'Total',
        }
        
        # Domains that are known to be valid and reliable
        self.reliable_domains = {
            'usmba.ac.ma': 'USMBA',
            'sofamaroc.com': 'SOFA',
            'valeo.com': 'Valeo',
        }
        
        # Domains that are known to be invalid or problematic
        self.problematic_domains = {
            'tateandlyle.com': 'Tate & Lyle',
            'gtr.co.ma': 'GTR',
            'somafel.pt': 'Somafel',
            'ml.imptob.com': 'Imptob',
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
        
        # Timeout values
        self.dns_timeout = 3  # seconds (reduced to avoid lag)
        self.smtp_timeout = 5  # seconds (reduced to avoid lag)
        
    def _load_disposable_domains(self) -> Set[str]:
        """Load a list of known disposable email domains."""
        try:
            # Try to fetch from a public list
            response = requests.get(
                "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf",
                timeout=3  # Reduced timeout
            )
            if response.status_code == 200:
                return set(response.text.strip().split('\n'))
        except Exception as e:
            logger.warning(f"Could not load disposable domains list: {e}")
        
        # Fallback to a small built-in list
        return {
            'mailinator.com', 'guerrillamail.com', 'temp-mail.org', 'fakeinbox.com',
            'tempmail.com', '10minutemail.com', 'yopmail.com', 'throwawaymail.com'
        }
    
    def validate_format(self, email: str) -> bool:
        """Check if the email has a valid format using regex."""
        # First, use parseaddr to handle edge cases
        _, addr = parseaddr(email)
        if not addr or addr != email:
            return False
            
        return bool(re.match(self.email_regex, email))
    
    def get_dns_records(self, domain: str, record_type: str = 'MX') -> List[str]:
        """Get DNS records for a domain with caching."""
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
    
    def verify_smtp(self, email: str, mx_servers: List[str]) -> Tuple[bool, Optional[str]]:
        """
        Verify email existence by connecting to the SMTP server.
        Returns a tuple of (is_deliverable, reason)
        """
        if not mx_servers:
            return False, "No MX records found"
        
        # Extract domain for custom handling
        domain = email.split('@')[1]
        
        # Use different sender addresses
        sender_emails = [
            "verify@example.com",
            "check@example.org",
            "test@example.net"
        ]
        
        # Try each MX server
        for mx in mx_servers[:2]:  # Only try the first 2 MX servers to avoid lag
            # Try each sender email
            for sender in sender_emails[:2]:  # Only try the first 2 sender emails
                try:
                    with smtplib.SMTP(mx, timeout=self.smtp_timeout) as smtp:
                        smtp.ehlo()
                        # Try to use STARTTLS if available
                        try:
                            if smtp.has_extn('STARTTLS'):
                                smtp.starttls()
                                smtp.ehlo()
                        except Exception:
                            # Continue if STARTTLS fails
                            pass
                        
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
                            return False, f"SMTP Error: {code} - {message_str}"
                    
                except (socket.timeout, socket.error, smtplib.SMTPException) as e:
                    logger.debug(f"SMTP error with {mx}: {str(e)}")
                    # Continue to next sender/MX
        
        return False, "All MX servers rejected connection or verification"
    
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
        Validate an email address with pattern-based intelligence.
        
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
        
        # Step 1: Check email format
        if not self.validate_format(email):
            result.reason = "Invalid email format"
            self.validation_cache[email] = result
            return result
        
        result.is_valid_format = True
        result.score = 0.4  # Valid format gives a base score
        
        # Extract domain and local part
        try:
            local_part, domain = email.split('@')
        except ValueError:
            result.reason = "Invalid email format (missing @ symbol)"
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
        
        # Step 3: Apply domain-specific intelligence based on patterns
        
        # Check if it's a major provider
        if domain in self.major_providers:
            result.provider = self.major_providers[domain]
            result.is_deliverable = True
            result.score = 0.8  # High confidence for major providers
            result.reason = f"Major provider ({result.provider}) - SMTP verification skipped"
            result.verification_method = "provider recognition"
            self.validation_cache[email] = result
            return result
        
        # Check if it's a known reliable domain
        if domain in self.reliable_domains:
            result.provider = self.reliable_domains[domain]
            
            # Still do SMTP check for confirmation
            if check_deliverability:
                is_deliverable, reason = self.verify_smtp(email, mx_records)
                result.is_deliverable = is_deliverable
                result.reason = reason if not is_deliverable else "Valid email address"
                result.verification_method = "SMTP verification"
                
                if is_deliverable:
                    result.score = 1.0  # Maximum confidence
                else:
                    # Even if SMTP fails, we have high confidence in these domains
                    result.score = 0.7
            else:
                result.score = 0.8
                result.reason = f"Reliable domain ({result.provider})"
                result.verification_method = "domain recognition"
            
            self.validation_cache[email] = result
            return result
        
        # Check if it's a known problematic domain
        if domain in self.problematic_domains:
            result.provider = self.problematic_domains[domain]
            result.is_deliverable = False
            result.score = 0.4  # Low confidence
            result.reason = f"Known problematic domain ({result.provider})"
            result.verification_method = "domain recognition"
            self.validation_cache[email] = result
            return result
        
        # Check if it's a regional provider
        if domain in self.regional_providers:
            result.provider = self.regional_providers[domain]
            
            # For regional providers, we'll be more lenient
            # Many of these return false negatives with SMTP checks
            result.is_deliverable = True
            result.score = 0.7  # Good confidence
            result.reason = f"Regional provider ({result.provider}) - Using relaxed validation"
            result.verification_method = "regional provider recognition"
            
            self.validation_cache[email] = result
            return result
        
        # Check if it's a domain that often gives false negatives
        if domain in self.lenient_domains:
            result.provider = self.lenient_domains[domain]
            
            # For these domains, we'll still do SMTP check but be lenient with the results
            if check_deliverability:
                is_deliverable, reason = self.verify_smtp(email, mx_records)
                
                # Even if SMTP check fails with "Mailbox unavailable",
                # we'll consider it potentially valid based on pattern analysis
                if not is_deliverable and reason == "Mailbox unavailable":
                    result.is_deliverable = True
                    result.score = 0.7  # Good confidence despite SMTP failure
                    result.reason = f"Domain ({result.provider}) often returns false negatives"
                    result.verification_method = "pattern analysis"
                else:
                    result.is_deliverable = is_deliverable
                    result.reason = reason if not is_deliverable else "Valid email address"
                    result.verification_method = "SMTP verification"
                    result.score = 0.8 if is_deliverable else 0.6
            else:
                result.score = 0.6
                result.reason = f"Lenient domain ({result.provider})"
                result.verification_method = "domain recognition"
            
            self.validation_cache[email] = result
            return result
        
        # For all other domains, perform standard SMTP verification
        if check_deliverability:
            is_deliverable, reason = self.verify_smtp(email, mx_records)
            result.is_deliverable = is_deliverable
            result.reason = reason if not is_deliverable else "Valid email address"
            result.verification_method = "SMTP verification"
            
            if is_deliverable:
                result.score += 0.4  # Significant boost for SMTP verification
            else:
                # For "Mailbox unavailable" responses, be slightly more lenient
                # based on pattern analysis showing these can be false negatives
                if reason == "Mailbox unavailable":
                    result.score -= 0.1
                else:
                    result.score -= 0.2
        
        # Ensure score is between 0 and 1
        result.score = max(0.0, min(1.0, result.score))
        
        # Cache the result
        self.validation_cache[email] = result
        return result
    
    def batch_validate(self, emails: List[str], check_deliverability: bool = True,
                      max_workers: int = 3) -> Dict[str, ValidationResult]:
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
                time.sleep(0.5)
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

# Example usage
if __name__ == "__main__":
    validator = SmartEmailValidator()
    
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