import re
import socket
import smtplib
import dns.resolver
import logging
from typing import Dict, Tuple, List, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EmailValidator:
    def __init__(self):
        # Regular expression for basic email format validation
        self.email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        # Cache for MX records to avoid repeated DNS lookups
        self.mx_cache: Dict[str, List[str]] = {}
        # Cache for validation results
        self.validation_cache: Dict[str, Dict] = {}
        
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
                   timeout: int = 10) -> Dict:
        """
        Verify email existence by connecting to the SMTP server.
        
        This uses the SMTP VRFY/RCPT TO commands to check if the email exists
        without actually sending an email.
        """
        domain = email.split('@')[1]
        result = {
            "is_deliverable": False,
            "smtp_check": False,
            "reason": None,
            "mx_used": None
        }
        
        if not mx_servers:
            result["reason"] = "No MX records found"
            return result
        
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
                    
                    result["mx_used"] = mx
                    
                    # SMTP status codes:
                    # 250 = Success
                    # 550 = Mailbox unavailable
                    # 551, 552, 553, 450, 451, 452 = Various temporary issues
                    # 503, 550, 551, 553 = Various permanent failures
                    
                    if code == 250:
                        result["is_deliverable"] = True
                        result["smtp_check"] = True
                        return result
                    elif code == 550:
                        result["reason"] = "Mailbox unavailable"
                        return result
                    else:
                        result["reason"] = f"SMTP Error: {code} - {message.decode('utf-8', errors='ignore')}"
                        # Continue to next MX if this one gave a temporary error
            
            except (socket.timeout, socket.error, smtplib.SMTPException) as e:
                logger.debug(f"SMTP error with {mx}: {str(e)}")
                # Continue to next MX server
        
        if not result["reason"]:
            result["reason"] = "All MX servers rejected connection or verification"
        return result
    
    def validate_email(self, email: str, check_deliverability: bool = True) -> Dict:
        """
        Validate an email address with multiple checks.
        
        Args:
            email: The email address to validate
            check_deliverability: Whether to check if the email can receive messages
            
        Returns:
            Dictionary with validation results
        """
        # Check cache first
        if email in self.validation_cache:
            return self.validation_cache[email]
        
        result = {
            "email": email,
            "is_valid_format": False,
            "has_mx_records": False,
            "is_deliverable": None,
            "full_result": {}
        }
        
        # Step 1: Check email format
        if not self.validate_format(email):
            result["full_result"] = {"reason": "Invalid email format"}
            self.validation_cache[email] = result
            return result
        
        result["is_valid_format"] = True
        
        # Extract domain
        domain = email.split('@')[1]
        
        # Step 2: Check MX records
        mx_records = self.get_mx_records(domain)
        if not mx_records:
            result["full_result"] = {"reason": "No MX records found"}
            self.validation_cache[email] = result
            return result
        
        result["has_mx_records"] = True
        
        # Step 3: Check deliverability if requested
        if check_deliverability:
            smtp_result = self.verify_smtp(email, mx_records)
            result["is_deliverable"] = smtp_result["is_deliverable"]
            result["full_result"] = smtp_result
        
        # Cache the result
        self.validation_cache[email] = result
        return result
    
    def batch_validate(self, emails: List[str], check_deliverability: bool = True) -> Dict[str, Dict]:
        """Validate multiple email addresses."""
        results = {}
        for email in emails:
            results[email] = self.validate_email(email, check_deliverability)
        return results

# Example usage
if __name__ == "__main__":
    validator = EmailValidator()
    
    # Test a single email
    email_to_test = input("Enter an email to validate: ")
    result = validator.validate_email(email_to_test)
    
    print("\nValidation Results:")
    print(f"Email: {result['email']}")
    print(f"Valid Format: {result['is_valid_format']}")
    print(f"Has MX Records: {result['has_mx_records']}")
    print(f"Is Deliverable: {result['is_deliverable']}")
    
    if result['full_result'].get('reason'):
        print(f"Reason: {result['full_result']['reason']}")
    
    # Batch validation example
    print("\nBatch Validation Example:")
    print("Enter multiple emails separated by commas:")
    batch_emails = input().split(',')
    batch_results = validator.batch_validate([email.strip() for email in batch_emails])
    
    for email, res in batch_results.items():
        print(f"\n{email}: {'✓ Valid' if res['is_deliverable'] else '✗ Invalid'}")
        if not res['is_deliverable'] and res['full_result'].get('reason'):
            print(f"  Reason: {res['full_result']['reason']}")