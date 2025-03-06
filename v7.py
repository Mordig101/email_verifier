import re
import socket
import smtplib
import dns.resolver
import logging
import time
import random
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from email.utils import parseaddr
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class VerificationResult:
    email: str
    exists: bool
    reason: str
    method: str
    details: Optional[Dict[str, Any]] = None
    
    def __str__(self) -> str:
        mark = "✓" if self.exists else "✗"
        return f"{self.email}: {mark} ({self.method}) - {self.reason}"

class DirectEmailVerifier:
    def __init__(self):
        # Cache for DNS records
        self.dns_cache: Dict[str, List[str]] = {}
        
        # Cache for verification results
        self.result_cache: Dict[str, VerificationResult] = {}
        
        # Known major email providers
        self.major_providers = {
            'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 
            'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
            'aol.com', 'icloud.com', 'me.com', 'protonmail.com', 'zoho.com'
        }
        
        # Sender emails to use for verification
        self.sender_emails = [
            "verify@example.com",
            "check@example.org",
            "test@example.net"
        ]
        
        # Timeouts
        self.dns_timeout = 5  # seconds
        self.smtp_timeout = 10  # seconds
        
        # Maximum retries
        self.max_retries = 2
    
    def validate_format(self, email: str) -> bool:
        """Check if the email has a valid format."""
        # Use parseaddr to handle edge cases
        _, addr = parseaddr(email)
        if not addr or addr != email:
            return False
            
        # Basic regex check
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def get_mx_records(self, domain: str) -> List[str]:
        """Get MX records for a domain with caching."""
        # Check cache first
        if domain in self.dns_cache:
            return self.dns_cache[domain]
        
        try:
            records = dns.resolver.resolve(domain, 'MX', lifetime=self.dns_timeout)
            mx_servers = [str(x.exchange).rstrip('.') for x in records]
            # Sort by priority (lowest first)
            mx_servers.sort()
            self.dns_cache[domain] = mx_servers
            return mx_servers
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            logger.warning(f"No MX records found for domain {domain}: {e}")
            self.dns_cache[domain] = []
            return []
    
    def verify_email_direct(self, email: str) -> VerificationResult:
        """
        Verify if an email exists by directly connecting to the mail server.
        This is the main verification method that tries multiple approaches.
        """
        # Check cache first
        if email in self.result_cache:
            return self.result_cache[email]
        
        # Step 1: Validate email format
        if not self.validate_format(email):
            result = VerificationResult(
                email=email,
                exists=False,
                reason="Invalid email format",
                method="format_check"
            )
            self.result_cache[email] = result
            return result
        
        # Step 2: Extract domain and get MX records
        _, domain = email.split('@')
        mx_records = self.get_mx_records(domain)
        
        if not mx_records:
            result = VerificationResult(
                email=email,
                exists=False,
                reason="Domain has no mail servers",
                method="mx_check"
            )
            self.result_cache[email] = result
            return result
        
        # Step 3: Check if it's a major provider (which typically block verification)
        if domain in self.major_providers:
            result = VerificationResult(
                email=email,
                exists=True,  # Assume valid for major providers
                reason=f"Major provider ({domain}) - verification skipped",
                method="provider_check"
            )
            self.result_cache[email] = result
            return result
        
        # Step 4: Try multiple verification methods
        
        # Method 1: SMTP RCPT TO command (most reliable)
        rcpt_result = self._verify_with_rcpt(email, mx_records)
        if rcpt_result.reason == "Email address does not exist":
            # If we get a clear "does not exist" response, we can be confident
            self.result_cache[email] = rcpt_result
            return rcpt_result
        
        # Method 2: Try VRFY command (many servers disable this)
        vrfy_result = self._verify_with_vrfy(email, mx_records)
        if vrfy_result.reason == "Email address does not exist":
            # If VRFY gives a clear negative, trust it
            self.result_cache[email] = vrfy_result
            return vrfy_result
        
        # If both methods failed to give a clear answer, use the RCPT result
        # as it's generally more reliable
        self.result_cache[email] = rcpt_result
        return rcpt_result
    
    def _verify_with_rcpt(self, email: str, mx_records: List[str]) -> VerificationResult:
        """
        Verify email using SMTP RCPT TO command.
        This method tries to add the recipient and checks the server response.
        """
        for retry in range(self.max_retries):
            # Try different MX servers
            for mx in mx_records[:3]:  # Try up to 3 MX servers
                # Try different sender emails
                for sender in self.sender_emails:
                    try:
                        with smtplib.SMTP(mx, timeout=self.smtp_timeout) as smtp:
                            smtp.ehlo()
                            # Try STARTTLS if available
                            try:
                                if smtp.has_extn('STARTTLS'):
                                    smtp.starttls()
                                    smtp.ehlo()
                            except Exception:
                                pass
                            
                            # Set sender address
                            smtp.mail(sender)
                            
                            # Try to add recipient
                            code, message = smtp.rcpt(email)
                            
                            # Close connection
                            smtp.quit()
                            
                            # Interpret the response
                            if code == 250:
                                # 250 = Success, email exists
                                return VerificationResult(
                                    email=email,
                                    exists=True,
                                    reason="Email address exists",
                                    method="SMTP_RCPT"
                                )
                            elif code == 550:
                                # 550 = Mailbox unavailable, typically means the email doesn't exist
                                message_str = message.decode('utf-8', errors='ignore').lower()
                                
                                # Look for clear indicators that the email doesn't exist
                                if any(phrase in message_str for phrase in [
                                    "does not exist", "no such user", "user unknown",
                                    "user not found", "invalid recipient", "recipient rejected",
                                    "no mailbox", "mailbox not found"
                                ]):
                                    return VerificationResult(
                                        email=email,
                                        exists=False,
                                        reason="Email address does not exist",
                                        method="SMTP_RCPT",
                                        details={"code": code, "message": message_str}
                                    )
                                else:
                                    # Other 550 errors might be policy-related
                                    return VerificationResult(
                                        email=email,
                                        exists=False,
                                        reason=f"Mailbox unavailable: {message_str}",
                                        method="SMTP_RCPT",
                                        details={"code": code, "message": message_str}
                                    )
                            elif code in (450, 451, 452):
                                # Temporary failures, try next server
                                continue
                            else:
                                # Other responses
                                message_str = message.decode('utf-8', errors='ignore')
                                return VerificationResult(
                                    email=email,
                                    exists=False,
                                    reason=f"SMTP Error: {code} - {message_str}",
                                    method="SMTP_RCPT",
                                    details={"code": code, "message": message_str}
                                )
                    
                    except (socket.timeout, socket.error, smtplib.SMTPException) as e:
                        logger.debug(f"SMTP error with {mx}: {str(e)}")
                        # Continue to next sender/MX
            
            # Add delay between retries
            if retry < self.max_retries - 1:
                time.sleep(2 ** retry)  # Exponential backoff
        
        # If we get here, all attempts failed
        return VerificationResult(
            email=email,
            exists=False,
            reason="Could not verify email (all servers rejected connection)",
            method="SMTP_RCPT"
        )
    
    def _verify_with_vrfy(self, email: str, mx_records: List[str]) -> VerificationResult:
        """
        Verify email using SMTP VRFY command.
        Many servers disable this command, but it's worth trying as a fallback.
        """
        for mx in mx_records[:2]:  # Try up to 2 MX servers
            try:
                with smtplib.SMTP(mx, timeout=self.smtp_timeout) as smtp:
                    smtp.ehlo()
                    # Try VRFY command
                    code, message = smtp.verify(email.split('@')[0])  # VRFY uses just the username
                    
                    # Close connection
                    smtp.quit()
                    
                    # Interpret the response
                    if code == 250:
                        # 250 = Success, user exists
                        return VerificationResult(
                            email=email,
                            exists=True,
                            reason="Email address exists",
                            method="SMTP_VRFY"
                        )
                    elif code == 550:
                        # 550 = User not found
                        return VerificationResult(
                            email=email,
                            exists=False,
                            reason="Email address does not exist",
                            method="SMTP_VRFY"
                        )
                    elif code == 502 or code == 252:
                        # 502 = Command not implemented
                        # 252 = Cannot verify user but will accept message and attempt delivery
                        return VerificationResult(
                            email=email,
                            exists=True,  # Assume exists if server doesn't reject outright
                            reason="Server does not support verification",
                            method="SMTP_VRFY"
                        )
                    else:
                        # Other responses
                        message_str = message.decode('utf-8', errors='ignore')
                        return VerificationResult(
                            email=email,
                            exists=False,
                            reason=f"VRFY Error: {code} - {message_str}",
                            method="SMTP_VRFY"
                        )
            
            except (socket.timeout, socket.error, smtplib.SMTPException) as e:
                logger.debug(f"SMTP VRFY error with {mx}: {str(e)}")
                # Continue to next MX
        
        # If we get here, VRFY is not supported or failed
        return VerificationResult(
            email=email,
            exists=False,
            reason="VRFY command not supported by mail servers",
            method="SMTP_VRFY"
        )
    
    def batch_verify(self, emails: List[str], max_workers: int = 3) -> Dict[str, VerificationResult]:
        """
        Verify multiple email addresses in parallel.
        
        Args:
            emails: List of email addresses to verify
            max_workers: Maximum number of parallel workers
        """
        results = {}
        
        # For small batches, don't use parallelism
        if len(emails) <= 3:
            for email in emails:
                results[email] = self.verify_email_direct(email)
                # Add a small delay between checks
                time.sleep(1)
            return results
        
        # For larger batches, use parallel processing
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_email = {
                executor.submit(self.verify_email_direct, email): email 
                for email in emails
            }
            
            # Collect results as they complete
            for future in future_to_email:
                email = future_to_email[future]
                try:
                    results[email] = future.result()
                except Exception as e:
                    logger.error(f"Error verifying {email}: {e}")
                    # Create a failed result
                    results[email] = VerificationResult(
                        email=email,
                        exists=False,
                        reason=f"Verification error: {str(e)}",
                        method="error"
                    )
        
        return results

# Example usage
if __name__ == "__main__":
    verifier = DirectEmailVerifier()
    
    # Test a single email
    email_to_test = input("Enter an email to verify: ")
    result = verifier.verify_email_direct(email_to_test)
    
    print("\nVerification Result:")
    print(result)
    if result.details:
        print(f"Details: {result.details}")
    
    # Batch verification example
    print("\nBatch Verification Example:")
    print("Enter multiple emails separated by commas:")
    batch_emails = input().split(',')
    batch_results = verifier.batch_verify([email.strip() for email in batch_emails])
    
    for email, res in batch_results.items():
        print(f"\n{res}")
        if res.details:
            print(f"  Details: {res.details}")