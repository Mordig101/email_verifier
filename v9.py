import re
import requests
import json
import logging
import time
import random
import dns.resolver
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class VerificationResult:
    email: str
    exists: bool
    reason: str
    provider: str
    confidence: float  # 0-1 scale
    details: Optional[Dict[str, Any]] = None
    
    def __str__(self) -> str:
        mark = "✓" if self.exists else "✗"
        return f"{self.email}: {mark} ({self.provider}, {self.confidence:.2f}) - {self.reason}"

class APIEmailVerifier:
    def __init__(self):
        # Cache for verification results
        self.result_cache: Dict[str, VerificationResult] = {}
        
        # Known email providers and their API endpoints
        self.provider_apis = {
            'gmail.com': 'https://accounts.google.com/_/lookup/accountlookup',
            'googlemail.com': 'https://accounts.google.com/_/lookup/accountlookup',
            'outlook.com': 'https://login.microsoftonline.com/common/GetCredentialType',
            'hotmail.com': 'https://login.microsoftonline.com/common/GetCredentialType',
            'live.com': 'https://login.microsoftonline.com/common/GetCredentialType',
            'yahoo.com': 'https://login.yahoo.com/account/challenge/username',
        }
        
        # User agents to rotate
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
        ]
    
    def get_random_user_agent(self) -> str:
        """Get a random user agent to avoid detection."""
        return random.choice(self.user_agents)
    
    def validate_format(self, email: str) -> bool:
        """Check if the email has a valid format."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def get_mx_records(self, domain: str) -> List[str]:
        """Get MX records for a domain to identify the mail provider."""
        try:
            records = dns.resolver.resolve(domain, 'MX', lifetime=5)
            mx_servers = [str(x.exchange).rstrip('.').lower() for x in records]
            return mx_servers
        except Exception as e:
            logger.warning(f"Error getting MX records for {domain}: {e}")
            return []
    
    def identify_provider(self, email: str) -> str:
        """Identify the email provider based on the domain and MX records."""
        _, domain = email.split('@')
        
        # Check if it's a known provider
        if domain in self.provider_apis:
            return domain
        
        # Check MX records to identify the provider
        mx_records = self.get_mx_records(domain)
        
        # Look for known providers in MX records
        for mx in mx_records:
            if 'google' in mx or 'gmail' in mx:
                return 'gmail.com'
            elif 'outlook' in mx or 'microsoft' in mx or 'office365' in mx:
                return 'outlook.com'
            elif 'yahoo' in mx:
                return 'yahoo.com'
        
        # If we can't identify the provider, return the domain
        return domain
    
    def verify_email(self, email: str) -> VerificationResult:
        """
        Verify if an email exists by using provider-specific APIs.
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
                provider="unknown",
                confidence=1.0
            )
            self.result_cache[email] = result
            return result
        
        # Step 2: Identify the provider
        provider = self.identify_provider(email)
        
        # Step 3: Verify based on provider
        if provider == 'gmail.com' or provider == 'googlemail.com':
            result = self._verify_google(email)
        elif provider in ['outlook.com', 'hotmail.com', 'live.com']:
            result = self._verify_microsoft(email)
        elif provider == 'yahoo.com':
            result = self._verify_yahoo(email)
        else:
            # For unknown providers, use a combination of methods
            result = self._verify_unknown(email, provider)
        
        # Cache and return the result
        self.result_cache[email] = result
        return result
    
    def _verify_google(self, email: str) -> VerificationResult:
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
                        provider="Google",
                        confidence=0.9,
                        details={"response": response_text[:100]}
                    )
                elif '"gf.uar",2,' in response_text or '"gf.alr",2,' in response_text:
                    # These patterns indicate the email exists
                    return VerificationResult(
                        email=email,
                        exists=True,
                        reason="Email address exists",
                        provider="Google",
                        confidence=0.9,
                        details={"response": response_text[:100]}
                    )
            
            # If we can't determine from the response, assume it might exist
            return VerificationResult(
                email=email,
                exists=True,
                reason="Could not definitively determine if email exists",
                provider="Google",
                confidence=0.5,
                details={"status_code": response.status_code}
            )
        
        except Exception as e:
            logger.error(f"Error verifying Google email {email}: {e}")
            return VerificationResult(
                email=email,
                exists=False,
                reason=f"Verification error: {str(e)}",
                provider="Google",
                confidence=0.3
            )
    
    def _verify_microsoft(self, email: str) -> VerificationResult:
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
                            provider="Microsoft",
                            confidence=0.9,
                            details={"response": data}
                        )
                    elif data['IfExistsResult'] == 1:
                        # 1 indicates the email doesn't exist
                        return VerificationResult(
                            email=email,
                            exists=False,
                            reason="Email address does not exist",
                            provider="Microsoft",
                            confidence=0.9,
                            details={"response": data}
                        )
                
                # If ThrottleStatus is in the response, the account might exist
                if 'ThrottleStatus' in data and data['ThrottleStatus'] == 1:
                    return VerificationResult(
                        email=email,
                        exists=True,
                        reason="Email address likely exists (throttled)",
                        provider="Microsoft",
                        confidence=0.7,
                        details={"response": data}
                    )
            
            # If we can't determine from the response, assume it might exist
            return VerificationResult(
                email=email,
                exists=True,
                reason="Could not definitively determine if email exists",
                provider="Microsoft",
                confidence=0.5,
                details={"status_code": response.status_code}
            )
        
        except Exception as e:
            logger.error(f"Error verifying Microsoft email {email}: {e}")
            return VerificationResult(
                email=email,
                exists=False,
                reason=f"Verification error: {str(e)}",
                provider="Microsoft",
                confidence=0.3
            )
    
    def _verify_yahoo(self, email: str) -> VerificationResult:
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
                        provider="Yahoo",
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
                        provider="Yahoo",
                        confidence=0.9,
                        details={"response": response_text[:100]}
                    )
            
            # If we can't determine from the response, assume it might exist
            return VerificationResult(
                email=email,
                exists=True,
                reason="Could not definitively determine if email exists",
                provider="Yahoo",
                confidence=0.5,
                details={"status_code": response.status_code}
            )
        
        except Exception as e:
            logger.error(f"Error verifying Yahoo email {email}: {e}")
            return VerificationResult(
                email=email,
                exists=False,
                reason=f"Verification error: {str(e)}",
                provider="Yahoo",
                confidence=0.3
            )
    
    def _verify_unknown(self, email: str, provider: str) -> VerificationResult:
        """
        Verify email for unknown providers using a combination of methods:
        1. Check MX records
        2. Check for common patterns in the domain
        3. Use SMTP verification as a fallback
        """
        # For unknown providers, we'll use a combination of methods
        # and assign a confidence score based on the results
        
        confidence = 0.5  # Start with neutral confidence
        
        # Step 1: Check if the domain has MX records
        mx_records = self.get_mx_records(email.split('@')[1])
        if not mx_records:
            return VerificationResult(
                email=email,
                exists=False,
                reason="Domain has no mail servers",
                provider=provider,
                confidence=0.8
            )
        else:
            confidence += 0.1  # Increase confidence if MX records exist
        
        # Step 2: Check if it's a corporate domain
        domain = email.split('@')[1]
        if '.' in domain.split('.')[-2]:  # Check for subdomains like mail.company.com
            confidence += 0.1  # Corporate domains are more likely to be valid
        
        # Step 3: Check for common patterns in the email
        username = email.split('@')[0]
        if len(username) < 4:
            confidence -= 0.1  # Very short usernames are less likely
        
        if re.match(r'^[a-zA-Z]+\.[a-zA-Z]+$', username):  # firstname.lastname pattern
            confidence += 0.1  # Common corporate email pattern
        
        # Step 4: Use SMTP verification as a fallback
        # This would normally call an SMTP verification function
        # But we'll skip it here for simplicity
        
        # Determine existence based on confidence
        exists = confidence >= 0.6
        
        return VerificationResult(
            email=email,
            exists=exists,
            reason=f"Determined based on domain analysis (confidence: {confidence:.2f})",
            provider=provider,
            confidence=confidence
        )
    
    def batch_verify(self, emails: List[str]) -> Dict[str, VerificationResult]:
        """
        Verify multiple email addresses.
        """
        results = {}
        
        for email in emails:
            results[email] = self.verify_email(email)
            # Add a delay between checks to avoid rate limiting
            time.sleep(random.uniform(1, 2))
        
        return results

# Example usage
if __name__ == "__main__":
    verifier = APIEmailVerifier()
    
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