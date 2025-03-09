import re
import socket
import smtplib
import dns.resolver
import logging
import time
import random
import requests
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    email: str
    is_valid_format: bool = False
    has_mx_records: bool = False
    is_deliverable: Optional[bool] = None
    is_disposable: bool = False
    is_role_account: bool = False
    score: float = 0.0  # 0-1 confidence score
    provider: Optional[str] = None
    reason: Optional[str] = None

class AdvancedEmailValidator:
    def __init__(self):
        # Regular expression for basic email format validation
        self.email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        # Cache for MX records to avoid repeated DNS lookups
        self.mx_cache: Dict[str, List[str]] = {}
        
        # Cache for validation results
        self.validation_cache: Dict[str, ValidationResult] = {}
        
        # Known major email providers that block SMTP verification
        self.major_providers = {
            'yahoo.com': 'Yahoo',
            
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
        
        # Common disposable email domains
        self.disposable_domains: Set[str] = self._load_disposable_domains()
        
        # Common role-based email prefixes
        self.role_prefixes = {
            'admin', 'info', 'support', 'sales', 'contact', 'help',
            'webmaster', 'postmaster', 'hostmaster', 'abuse', 'noreply',
            'no-reply', 'team', 'marketing', 'billing', 'office', 'mail',
            'jobs', 'career', 'hr', 'service', 'enquiry', 'inquiry'
        }
        
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
    
    def validate_format(self, email: str) -> bool:
        """Check if the email has a valid format using regex."""
        return bool(re.match(self.email_regex, email))
    
    def get_mx_records(self, domain: str) -> List[str]:
        """Get MX records for a domain with caching."""
        if domain in self.mx_cache:
            return self.mx_cache[domain]
        
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_servers = [str(x.exchange).rstrip('.') for x in mx_records]
            # Sort by priority (lowest first)
            mx_servers.sort()
            self.mx_cache[domain] = mx_servers
            return mx_servers
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            logger.warning(f"No MX records found for domain: {domain}")
            return []
    
    def verify_smtp(self, email: str, mx_servers: List[str], 
                   sender_email: str = "verify@example.com", 
                   timeout: int = 10) -> Tuple[bool, Optional[str]]:
        """
        Verify email existence by connecting to the SMTP server.
        Returns a tuple of (is_deliverable, reason)
        """
        if not mx_servers:
            return False, "No MX records found"
        
        for mx in mx_servers:
            try:
                with smtplib.SMTP(mx, timeout=timeout) as smtp:
                    smtp.ehlo()
                    # Try to use STARTTLS if available
                    if smtp.has_extn('STARTTLS'):
                        smtp.starttls()
                        smtp.ehlo()
                    
                    # Some servers require a sender address
                    smtp.mail(sender_email)
                    
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
                        # Continue to next MX if this one gave a temporary error
                        if code in (450, 451, 452):
                            continue
                        return False, f"SMTP Error: {code} - {message_str}"
            
            except (socket.timeout, socket.error, smtplib.SMTPException) as e:
                logger.debug(f"SMTP error with {mx}: {str(e)}")
                # Continue to next MX server
        
        return False, "All MX servers rejected connection or verification"
    
    def check_major_provider(self, domain: str, local_part: str) -> Tuple[bool, float]:
        """
        Special handling for major email providers that block SMTP verification.
        Returns a tuple of (likely_valid, confidence_score)
        """
        provider = self.major_providers.get(domain)
        if not provider:
            return False, 0.0
        
        # Basic checks for major providers
        if provider == "Google":  # Gmail
            # Gmail username rules: 6-30 chars, letters, numbers, dots
            if len(local_part) < 6 or len(local_part) > 30:
                return False, 0.3
            if not re.match(r'^[a-zA-Z0-9.]+$', local_part):
                return False, 0.3
            return True, 0.8
            
        elif provider == "Microsoft":  # Outlook, Hotmail, Live
            # Microsoft username rules: 1-64 chars, letters, numbers, dots, underscores, dashes
            if len(local_part) < 1 or len(local_part) > 64:
                return False, 0.3
            if not re.match(r'^[a-zA-Z0-9._%+-]+$', local_part):
                return False, 0.3
            return True, 0.8
            
        elif provider == "Yahoo":
            # Yahoo username rules: 4-32 chars, letters, numbers, underscores
            if len(local_part) < 4 or len(local_part) > 32:
                return False, 0.3
            if not re.match(r'^[a-zA-Z0-9_]+$', local_part):
                return False, 0.3
            return True, 0.8
            
        # For other major providers, we'll assume valid with medium confidence
        return True, 0.7
    
    def is_disposable(self, domain: str) -> bool:
        """Check if the email domain is a known disposable email service."""
        return domain in self.disposable_domains
    
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
        
        # Step 1: Check email format
        if not self.validate_format(email):
            result.reason = "Invalid email format"
            self.validation_cache[email] = result
            return result
        
        result.is_valid_format = True
        result.score = 0.3  # Valid format gives a base score
        
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
        
        # Step 2: Check MX records
        mx_records = self.get_mx_records(domain)
        if not mx_records:
            result.reason = "No MX records found"
            self.validation_cache[email] = result
            return result
        
        result.has_mx_records = True
        result.score += 0.2  # Having MX records increases score
        
        # Step 3: Check if it's a major provider
        result.provider = self.major_providers.get(domain)
        if result.provider:
            # Special handling for major providers
            likely_valid, confidence = self.check_major_provider(domain, local_part)
            if likely_valid:
                result.is_deliverable = True
                result.score = max(result.score, confidence)
                result.reason = f"Major provider ({result.provider}) - SMTP verification skipped"
                
                # Cache and return early for major providers
                self.validation_cache[email] = result
                return result
        
        # Step 4: Check deliverability if requested and not a major provider
        if check_deliverability:
            # Add a small random delay to avoid rate limiting
            time.sleep(random.uniform(0.5, 2.0))
            
            is_deliverable, reason = self.verify_smtp(email, mx_records)
            result.is_deliverable = is_deliverable
            result.reason = reason
            
            if is_deliverable:
                result.score += 0.5  # Significant boost for SMTP verification
            else:
                result.score -= 0.2  # Reduce score for failed SMTP verification
        
        # Ensure score is between 0 and 1
        result.score = max(0.0, min(1.0, result.score))
        
        # Cache the result
        self.validation_cache[email] = result
        return result
    
    def batch_validate(self, emails: List[str], check_deliverability: bool = True) -> Dict[str, ValidationResult]:
        """Validate multiple email addresses."""
        results = {}
        for email in emails:
            results[email] = self.validate_email(email, check_deliverability)
            # Add a small delay between checks
            time.sleep(random.uniform(0.1, 0.5))
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
    validator = AdvancedEmailValidator()
    
    # Test a single email
    email_to_test = input("Enter an email to validate: ")
    result = validator.validate_email(email_to_test)
    
    print("\nValidation Results:")
    print(f"Email: {result.email}")
    print(f"Valid Format: {result.is_valid_format}")
    print(f"Has MX Records: {result.has_mx_records}")
    print(f"Is Deliverable: {result.is_deliverable}")
    print(f"Provider: {result.provider or 'Unknown'}")
    print(f"Is Disposable: {result.is_disposable}")
    print(f"Is Role Account: {result.is_role_account}")
    print(f"Confidence Score: {result.score:.2f}")
    
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
        if res.reason:
            print(f"  Reason: {res.reason}")