import re
import socket
import smtplib
import dns.resolver
import logging
import time
import random
import requests
import json
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
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
    confidence: float  # 0-1 scale
    details: Optional[Dict[str, Any]] = None
    
    def __str__(self) -> str:
        mark = "✓" if self.exists else "✗"
        return f"{self.email}: {mark} ({self.method}, {self.confidence:.2f}) - {self.reason}"

class MultiMethodVerifier:
    def __init__(self):
        # Cache for verification results
        self.result_cache: Dict[str, VerificationResult] = {}
        
        # Cache for DNS records
        self.dns_cache: Dict[str, Dict[str, List[str]]] = {}
        
        # Known major email providers
        self.major_providers = {
            'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 
            'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
            'aol.com', 'icloud.com', 'me.com', 'protonmail.com', 'zoho.com'
        }
        
        # Known corporate domains that often block verification
        self.corporate_domains = {
            'microsoft.com', 'apple.com', 'amazon.com', 'google.com',
            'facebook.com', 'twitter.com', 'linkedin.com', 'netflix.com',
            'ibm.com', 'oracle.com', 'salesforce.com', 'adobe.com',
            'cisco.com', 'intel.com', 'hp.com', 'dell.com', 'sap.com',
            'siemens.com', 'samsung.com', 'sony.com', 'toyota.com',
            'bmw.com', 'mercedes-benz.com', 'coca-cola.com', 'pepsi.com',
            'nestle.com', 'ma.nestle.com', 'unilever.com', 'procter.com',
            'shell.com', 'bp.com', 'exxon.com', 'chevron.com',
            'valeo.com', 'tateandlyle.com', 'lydec.co.ma', 'usmba.ac.ma',
            'avanzit.ma', 'jacobs-esa.com', 'newrest.eu', 'sopriam-ona.com',
            'snep.ma', 'total.co.ma', 'gbh.ma', 'sofamaroc.com'
        }
        
        # Known valid emails (whitelist)
        self.valid_emails = {
            
        }
        
        # Known invalid emails (blacklist)
        self.invalid_emails = {
            
        }
        
        # User agents to rotate
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
        ]
        
        # Timeouts
        self.dns_timeout = 5  # seconds
        self.smtp_timeout = 10  # seconds
        
        # Maximum retries
        self.max_retries = 2
    
    def get_random_user_agent(self) -> str:
        """Get a random user agent to avoid detection."""
        return random.choice(self.user_agents)
    
    def validate_format(self, email: str) -> bool:
        """Check if the email has a valid format."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
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
    
    def verify_email(self, email: str) -> VerificationResult:
        """
        Verify if an email exists using multiple methods.
        This is the main entry point that orchestrates the verification process.
        """
        # Check cache first
        if email in self.result_cache:
            return self.result_cache[email]
        
        # Step 1: Check whitelist and blacklist
        if email in self.valid_emails:
            result = VerificationResult(
                email=email,
                exists=True,
                reason="Known valid email",
                method="whitelist",
                confidence=1.0
            )
            self.result_cache[email] = result
            return result
        
        if email in self.invalid_emails:
            result = VerificationResult(
                email=email,
                exists=False,
                reason="Known invalid email",
                method="blacklist",
                confidence=1.0
            )
            self.result_cache[email] = result
            return result
        
        # Step 2: Validate email format
        if not self.validate_format(email):
            result = VerificationResult(
                email=email,
                exists=False,
                reason="Invalid email format",
                method="format_check",
                confidence=1.0
            )
            self.result_cache[email] = result
            return result
        
        # Step 3: Extract domain and check DNS records
        _, domain = email.split('@')
        mx_records = self.get_dns_records(domain, 'MX')
        
        if not mx_records:
            result = VerificationResult(
                email=email,
                exists=False,
                reason="Domain has no mail servers",
                method="mx_check",
                confidence=0.9
            )
            self.result_cache[email] = result
            return result
        
        # Step 4: Determine which verification methods to use based on the domain
        
        # For major providers, use API verification
        if domain in self.major_providers:
            result = self._verify_api(email)
            
            # If API verification is inconclusive, try SMTP
            if result.confidence < 0.7:
                smtp_result = self._verify_smtp(email, mx_records)
                
                # If SMTP gives a more confident result, use it
                if smtp_result.confidence > result.confidence:
                    result = smtp_result
        
        # For corporate domains, use a combination of methods
        elif domain in self.corporate_domains or any(domain.endswith(f".{corp}") for corp in self.corporate_domains):
            # Try API first
            result = self._verify_api(email)
            
            # If API is inconclusive, try pattern analysis
            if result.confidence < 0.7:
                pattern_result = self._verify_pattern(email)
                
                # If pattern analysis is more confident, use it
                if pattern_result.confidence > result.confidence:
                    result = pattern_result
                
                # If still inconclusive, try SMTP as a last resort
                if result.confidence < 0.7:
                    smtp_result = self._verify_smtp(email, mx_records)
                    
                    # If SMTP gives a more confident result, use it
                    if smtp_result.confidence > result.confidence:
                        result = smtp_result
        
        # For all other domains, try SMTP first, then fall back to pattern analysis
        else:
            result = self._verify_smtp(email, mx_records)
            
            # If SMTP is inconclusive, try pattern analysis
            if result.confidence < 0.7:
                pattern_result = self._verify_pattern(email)
                
                # If pattern analysis is more confident, use it
                if pattern_result.confidence > result.confidence:
                    result = pattern_result
        
        # Cache and return the result
        self.result_cache[email] = result
        return result
    
    def _verify_api(self, email: str) -> VerificationResult:
        """
        Verify email using provider-specific APIs.
        This method tries to use the login APIs of major providers.
        """
        _, domain = email.split('@')
        
        # Determine which API to use based on the domain
        if domain in ['gmail.com', 'googlemail.com'] or domain.endswith('.gmail.com'):
            return self._verify_google_api(email)
        elif domain in ['outlook.com', 'hotmail.com', 'live.com', 'msn.com'] or domain.endswith('.outlook.com'):
            return self._verify_microsoft_api(email)
        elif domain in ['yahoo.com', 'yahoo.co.uk'] or domain.endswith('.yahoo.com'):
            return self._verify_yahoo_api(email)
        else:
            # For unknown providers, return a low-confidence result
            return VerificationResult(
                email=email,
                exists=True,  # Assume it might exist
                reason="No API available for this provider",
                method="api_unavailable",
                confidence=0.3
            )
    
    def _verify_google_api(self, email: str) -> VerificationResult:
        """Verify email using Google's account lookup API."""
        try:
            session = requests.Session()
            
            # Set headers to look like a browser
            headers = {
                'User-Agent': self.get_random_user_agent(),
                'Accept': 'application/json',
                'Accept-Language': 'en-US,en;q=0.9',
                'Referer': 'https://accounts.google.com/',
                'Content-Type': 'application/json',
                'X-Same-Domain': '1',
                'Origin': 'https://accounts.google.com',
            }
            
            # Prepare the request payload
            payload = {
                'email': email,
                'flowName': 'GlifWebSignIn',
                'flowEntry': 'ServiceLogin',
                'checkConnection': 'false',
                'f.req': json.dumps([email, 0, 1, 1])
            }
            
            # Make the request
            response = session.post(
                'https://accounts.google.com/_/lookup/accountlookup?hl=en',
                headers=headers,
                data=payload
            )
            
            # Check if the response indicates the email exists
            if response.status_code == 200:
                response_text = response.text
                
                # Google's response is a bit tricky to parse
                # It contains a JSON array inside a JavaScript array
                if '"gf.alr",1,' in response_text or '"gf.uar",1,' in response_text:
                    # These patterns indicate the email doesn't exist
                    return VerificationResult(
                        email=email,
                        exists=False,
                        reason="Email address does not exist",
                        method="google_api",
                        confidence=0.9,
                        details={"response": response_text[:100]}
                    )
                elif '"gf.uar",2,' in response_text or '"gf.alr",2,' in response_text:
                    # These patterns indicate the email exists
                    return VerificationResult(
                        email=email,
                        exists=True,
                        reason="Email address exists",
                        method="google_api",
                        confidence=0.9,
                        details={"response": response_text[:100]}
                    )
            
            # If we can't determine from the response, return a low-confidence result
            return VerificationResult(
                email=email,
                exists=True,  # Assume it might exist
                reason="Could not definitively determine if email exists",
                method="google_api",
                confidence=0.5,
                details={"status_code": response.status_code}
            )
        
        except Exception as e:
            logger.error(f"Error verifying Google email {email}: {e}")
            return VerificationResult(
                email=email,
                exists=True,  # Assume it might exist
                reason=f"API verification error: {str(e)}",
                method="google_api",
                confidence=0.3
            )
    
    def _verify_microsoft_api(self, email: str) -> VerificationResult:
        """Verify email using Microsoft's credential type API."""
        try:
            session = requests.Session()
            
            # Set headers to look like a browser
            headers = {
                'User-Agent': self.get_random_user_agent(),
                'Accept': 'application/json',
                'Accept-Language': 'en-US,en;q=0.9',
                'Referer': 'https://login.microsoftonline.com/',
                'Content-Type': 'application/json',
                'Origin': 'https://login.microsoftonline.com',
            }
            
            # Prepare the request payload
            payload = {
                'Username': email,
                'isOtherIdpSupported': True,
                'checkPhones': False,
                'isRemoteNGCSupported': True,
                'isCookieBannerShown': False,
                'isFidoSupported': True,
                'originalRequest': '',
                'country': 'US',
                'forceotclogin': False,
                'isExternalFederationDisallowed': False,
                'isRemoteConnectSupported': False,
                'federationFlags': 0,
                'isSignup': False,
                'flowToken': '',
                'isAccessPassSupported': True
            }
            
            # Make the request
            response = session.post(
                'https://login.microsoftonline.com/common/GetCredentialType',
                headers=headers,
                json=payload
            )
            
            # Check if the response indicates the email exists
            if response.status_code == 200:
                data = response.json()
                
                # Check for specific indicators in the response
                if 'IfExistsResult' in data:
                    if data['IfExistsResult'] == 0:
                        # 0 indicates the email exists
                        return VerificationResult(
                            email=email,
                            exists=True,
                            reason="Email address exists",
                            method="microsoft_api",
                            confidence=0.9,
                            details={"response": data}
                        )
                    elif data['IfExistsResult'] == 1:
                        # 1 indicates the email doesn't exist
                        return VerificationResult(
                            email=email,
                            exists=False,
                            reason="Email address does not exist",
                            method="microsoft_api",
                            confidence=0.9,
                            details={"response": data}
                        )
                
                # If ThrottleStatus is in the response, the account might exist
                if 'ThrottleStatus' in data and data['ThrottleStatus'] == 1:
                    return VerificationResult(
                        email=email,
                        exists=True,
                        reason="Email address likely exists (throttled)",
                        method="microsoft_api",
                        confidence=0.7,
                        details={"response": data}
                    )
            
            # If we can't determine from the response, return a low-confidence result
            return VerificationResult(
                email=email,
                exists=True,  # Assume it might exist
                reason="Could not definitively determine if email exists",
                method="microsoft_api",
                confidence=0.5,
                details={"status_code": response.status_code}
            )
        
        except Exception as e:
            logger.error(f"Error verifying Microsoft email {email}: {e}")
            return VerificationResult(
                email=email,
                exists=True,  # Assume it might exist
                reason=f"API verification error: {str(e)}",
                method="microsoft_api",
                confidence=0.3
            )
    
    def _verify_yahoo_api(self, email: str) -> VerificationResult:
        """Verify email using Yahoo's username challenge API."""
        try:
            session = requests.Session()
            
            # Set headers to look like a browser
            headers = {
                'User-Agent': self.get_random_user_agent(),
                'Accept': 'application/json',
                'Accept-Language': 'en-US,en;q=0.9',
                'Referer': 'https://login.yahoo.com/',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Origin': 'https://login.yahoo.com',
            }
            
            # First, get the session cookies
            session.get('https://login.yahoo.com/', headers=headers)
            
            # Prepare the request payload
            payload = {
                'username': email,
                'acrumb': '',  # This would normally be extracted from the page
                'sessionIndex': '',
                'displayName': '',
                'context': '',
                'deviceCapability': '{"pa":{"status":false}}',
                'crumb': ''  # This would normally be extracted from the page
            }
            
            # Make the request
            response = session.post(
                'https://login.yahoo.com/account/challenge/username',
                headers=headers,
                data=payload
            )
            
            # Check if the response indicates the email exists
            if response.status_code == 200:
                # Yahoo typically redirects to a password page if the email exists
                if 'password' in response.url:
                    return VerificationResult(
                        email=email,
                        exists=True,
                        reason="Email address exists (redirected to password page)",
                        method="yahoo_api",
                        confidence=0.9,
                        details={"redirect_url": response.url}
                    )
                
                # Check for error messages in the response
                response_text = response.text.lower()
                if 'we couldn\'t find' in response_text or 'no account with this email' in response_text:
                    return VerificationResult(
                        email=email,
                        exists=False,
                        reason="Email address does not exist",
                        method="yahoo_api",
                        confidence=0.9,
                        details={"response": response_text[:100]}
                    )
            
            # If we can't determine from the response, return a low-confidence result
            return VerificationResult(
                email=email,
                exists=True,  # Assume it might exist
                reason="Could not definitively determine if email exists",
                method="yahoo_api",
                confidence=0.5,
                details={"status_code": response.status_code}
            )
        
        except Exception as e:
            logger.error(f"Error verifying Yahoo email {email}: {e}")
            return VerificationResult(
                email=email,
                exists=True,  # Assume it might exist
                reason=f"API verification error: {str(e)}",
                method="yahoo_api",
                confidence=0.3
            )
    
    def _verify_smtp(self, email: str, mx_records: List[str]) -> VerificationResult:
        """
        Verify email using SMTP.
        This method tries to connect to the mail server and check if the recipient exists.
        """
        if not mx_records:
            return VerificationResult(
                email=email,
                exists=False,
                reason="No MX records found",
                method="smtp",
                confidence=0.8
            )
        
        # Extract domain for custom handling
        domain = email.split('@')[1]
        
        # Use different sender addresses
        sender_emails = [
            "verify@example.com",
            "check@example.org",
            "test@example.net"
        ]
        
        # Try each MX server
        for mx in mx_records[:2]:  # Only try the first 2 MX servers
            # Try each sender email
            for sender in sender_emails[:2]:  # Only try the first 2 sender emails
                # Try multiple times (with backoff)
                for attempt in range(self.max_retries):
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
                                return VerificationResult(
                                    email=email,
                                    exists=True,
                                    reason="Email address exists",
                                    method="smtp",
                                    confidence=0.9
                                )
                            elif code == 550:
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
                                        method="smtp",
                                        confidence=0.9,
                                        details={"code": code, "message": message_str}
                                    )
                                else:
                                    # Other 550 errors might be policy-related
                                    # For corporate domains, this often means the email exists
                                    # but the server is blocking verification
                                    if domain in self.corporate_domains or any(domain.endswith(f".{corp}") for corp in self.corporate_domains):
                                        return VerificationResult(
                                            email=email,
                                            exists=False,  # For corporate domains, assume it doesn't exist
                                            reason=f"Mailbox unavailable: {message_str}",
                                            method="smtp",
                                            confidence=0.7,
                                            details={"code": code, "message": message_str}
                                        )
                                    else:
                                        return VerificationResult(
                                            email=email,
                                            exists=False,
                                            reason=f"Mailbox unavailable: {message_str}",
                                            method="smtp",
                                            confidence=0.8,
                                            details={"code": code, "message": message_str}
                                        )
                            elif code in (450, 451, 452):
                                # Temporary failures, try next server
                                continue
                            else:
                                # Other responses
                                message_str = message.decode('utf-8', errors='ignore')
                                
                                # For corporate domains, assume the email doesn't exist
                                if domain in self.corporate_domains or any(domain.endswith(f".{corp}") for corp in self.corporate_domains):
                                    return VerificationResult(
                                        email=email,
                                        exists=False,
                                        reason=f"SMTP Error: {code} - {message_str}",
                                        method="smtp",
                                        confidence=0.7,
                                        details={"code": code, "message": message_str}
                                    )
                                else:
                                    return VerificationResult(
                                        email=email,
                                        exists=False,
                                        reason=f"SMTP Error: {code} - {message_str}",
                                        method="smtp",
                                        confidence=0.8,
                                        details={"code": code, "message": message_str}
                                    )
                        
                    except (socket.timeout, socket.error, smtplib.SMTPException) as e:
                        logger.debug(f"SMTP error with {mx}: {str(e)}")
                        # Continue to next attempt
                    
                    # Add delay between retries
                    if attempt < self.max_retries - 1:
                        time.sleep(2 ** attempt)  # Exponential backoff
        
        # If we get here, all attempts failed
        # For corporate domains, this often means the server is blocking verification
        if domain in self.corporate_domains or any(domain.endswith(f".{corp}") for corp in self.corporate_domains):
            return VerificationResult(
                email=email,
                exists=False,  # For corporate domains, assume it doesn't exist
                reason="Could not verify email (all servers rejected connection)",
                method="smtp",
                confidence=0.6
            )
        else:
            return VerificationResult(
                email=email,
                exists=False,
                reason="Could not verify email (all servers rejected connection)",
                method="smtp",
                confidence=0.7
            )
    
    def _verify_pattern(self, email: str) -> VerificationResult:
        """
        Verify email using pattern analysis.
        This method analyzes the email structure and domain to determine if it's likely valid.
        """
        username, domain = email.split('@')
        
        # Start with a neutral confidence
        confidence = 0.5
        
        # Step 1: Check username patterns
        
        # Very short usernames are less likely to be valid
        if len(username) < 3:
            confidence -= 0.1
        
        # Very long usernames are less likely to be valid
        if len(username) > 30:
            confidence -= 0.1
        
        # Common patterns for corporate emails
        if re.match(r'^[a-zA-Z]+\.[a-zA-Z]+$', username):  # firstname.lastname
            confidence += 0.1
        
        if re.match(r'^[a-zA-Z]+_[a-zA-Z]+$', username):  # firstname_lastname
            confidence += 0.1
        
        # Common patterns for personal emails
        if re.match(r'^[a-zA-Z]+\d{2,4}$', username):  # name followed by year
            confidence += 0.1
        
        # Random-looking usernames are less likely to be valid
        if re.match(r'^[a-zA-Z0-9]{8,}$', username) and not any(c.isalpha() for c in username):
            confidence -= 0.1
        
        # Step 2: Check domain patterns
        
        # Corporate domains are more likely to have valid emails
        if domain in self.corporate_domains or any(domain.endswith(f".{corp}") for corp in self.corporate_domains):
            confidence += 0.1
        
        # Subdomains are more likely to be corporate
        if domain.count('.') > 1:
            confidence += 0.1
        
        # Step 3: Check MX records
        mx_records = self.get_dns_records(domain, 'MX')
        if mx_records:
            confidence += 0.1
        
        # Step 4: Determine existence
        exists = confidence >= 0.6
        
        # Step 5: Adjust confidence based on domain type
        
        # For corporate domains, be more conservative
        if domain in self.corporate_domains or any(domain.endswith(f".{corp}") for corp in self.corporate_domains):
            # For corporate domains, we need stronger evidence
            if confidence < 0.7:
                exists = False
        
        # Return the result
        return VerificationResult(
            email=email,
            exists=exists,
            reason=f"Determined based on pattern analysis (confidence: {confidence:.2f})",
            method="pattern_analysis",
            confidence=confidence
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
                results[email] = self.verify_email(email)
                # Add a small delay between checks
                time.sleep(1)
            return results
        
        # For larger batches, use parallel processing
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_email = {
                executor.submit(self.verify_email, email): email 
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
                        method="error",
                        confidence=0.0
                    )
        
        return results

# Example usage
if __name__ == "__main__":
    verifier = MultiMethodVerifier()
    
    # Test a single email
    email_to_test = input("Enter an email to verify: ")
    result = verifier.verify_email(email_to_test)
    
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