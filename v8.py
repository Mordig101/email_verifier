import re
import requests
import logging
import time
import random
import tldextract
import dns.resolver
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class LoginVerificationResult:
    email: str
    exists: bool
    reason: str
    provider: str
    details: Optional[Dict[str, Any]] = None
    
    def __str__(self) -> str:
        mark = "✓" if self.exists else "✗"
        return f"{self.email}: {mark} ({self.provider}) - {self.reason}"

class LoginEmailVerifier:
    def __init__(self):
        # Cache for verification results
        self.result_cache: Dict[str, LoginVerificationResult] = {}
        
        # Known email providers and their login URLs
        self.provider_login_urls = {
            # Major providers
            'gmail.com': 'https://accounts.google.com/signin',
            'googlemail.com': 'https://accounts.google.com/signin',
            'outlook.com': 'https://login.live.com',
            'hotmail.com': 'https://login.live.com',
            'live.com': 'https://login.live.com',
            'yahoo.com': 'https://login.yahoo.com',
            'aol.com': 'https://login.aol.com',
            'protonmail.com': 'https://mail.proton.me/login',
            'zoho.com': 'https://accounts.zoho.com/signin',
            
            # Regional providers
            'mail.ru': 'https://account.mail.ru/login',
            'yandex.ru': 'https://passport.yandex.ru/auth',
            'menara.ma': 'https://webmail.menara.ma/',
            
            # Corporate providers often use Microsoft or Google
            'microsoft.com': 'https://login.microsoftonline.com',
            'office365.com': 'https://login.microsoftonline.com',
        }
        
        # Error messages that indicate an email doesn't exist
        self.nonexistent_email_phrases = {
            # Google
            'gmail.com': [
                "couldn't find your google account",
                "couldn't find your account",
                "no account found with that email"
            ],
            # Microsoft
            'outlook.com': [
                "we couldn't find an account with that username",
                "that microsoft account doesn't exist",
                "no account found"
            ],
            # Yahoo
            'yahoo.com': [
                "we couldn't find this account",
                "we don't recognize this email",
                "no account exists with this email address"
            ],
            # Generic phrases that many providers use
            'generic': [
                "email not found",
                "user not found",
                "account not found",
                "no account",
                "doesn't exist",
                "invalid email",
                "email address is incorrect"
            ]
        }
        
        # Error messages that indicate an email exists but password is wrong
        self.wrong_password_phrases = {
            # Google
            'gmail.com': [
                "wrong password",
                "incorrect password",
                "the password you entered is incorrect"
            ],
            # Microsoft
            'outlook.com': [
                "your account or password is incorrect",
                "the password is incorrect"
            ],
            # Yahoo
            'yahoo.com': [
                "invalid password",
                "incorrect password"
            ],
            # Generic phrases that many providers use
            'generic': [
                "wrong password",
                "incorrect password",
                "password is incorrect",
                "invalid password"
            ]
        }
        
        # Initialize headless browser options
        self.chrome_options = Options()
        self.chrome_options.add_argument("--headless")
        self.chrome_options.add_argument("--no-sandbox")
        self.chrome_options.add_argument("--disable-dev-shm-usage")
        self.chrome_options.add_argument("--disable-gpu")
        self.chrome_options.add_argument("--window-size=1920,1080")
        self.chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36")
    
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
    
    def identify_provider(self, email: str) -> Tuple[str, str]:
        """
        Identify the email provider based on the domain and MX records.
        Returns (provider_name, login_url)
        """
        _, domain = email.split('@')
        
        # Check if it's a known provider
        if domain in self.provider_login_urls:
            return domain, self.provider_login_urls[domain]
        
        # Check MX records to identify the provider
        mx_records = self.get_mx_records(domain)
        
        # Look for known providers in MX records
        for mx in mx_records:
            if 'google' in mx or 'gmail' in mx:
                return 'gmail.com', self.provider_login_urls['gmail.com']
            elif 'outlook' in mx or 'microsoft' in mx or 'office365' in mx:
                return 'outlook.com', self.provider_login_urls['outlook.com']
            elif 'yahoo' in mx:
                return 'yahoo.com', self.provider_login_urls['yahoo.com']
            elif 'protonmail' in mx or 'proton.me' in mx:
                return 'protonmail.com', self.provider_login_urls['protonmail.com']
            elif 'zoho' in mx:
                return 'zoho.com', self.provider_login_urls['zoho.com']
            elif 'mail.ru' in mx:
                return 'mail.ru', self.provider_login_urls['mail.ru']
            elif 'yandex' in mx:
                return 'yandex.ru', self.provider_login_urls['yandex.ru']
        
        # If we can't identify the provider, use a generic approach
        return 'unknown', None
    
    def verify_email_login(self, email: str) -> LoginVerificationResult:
        """
        Verify if an email exists by attempting to log in and analyzing the response.
        """
        # Check cache first
        if email in self.result_cache:
            return self.result_cache[email]
        
        # Step 1: Validate email format
        if not self.validate_format(email):
            result = LoginVerificationResult(
                email=email,
                exists=False,
                reason="Invalid email format",
                provider="unknown"
            )
            self.result_cache[email] = result
            return result
        
        # Step 2: Identify the provider
        provider, login_url = self.identify_provider(email)
        
        # If we couldn't identify a login URL, we can't verify
        if not login_url:
            result = LoginVerificationResult(
                email=email,
                exists=False,
                reason="Unknown email provider, can't verify",
                provider=provider
            )
            self.result_cache[email] = result
            return result
        
        # Step 3: Attempt login verification based on provider
        if provider == 'gmail.com' or provider == 'googlemail.com':
            result = self._verify_google_login(email)
        elif provider in ['outlook.com', 'hotmail.com', 'live.com', 'microsoft.com', 'office365.com']:
            result = self._verify_microsoft_login(email)
        elif provider == 'yahoo.com':
            result = self._verify_yahoo_login(email)
        else:
            # For other providers, use a generic approach
            result = self._verify_generic_login(email, login_url, provider)
        
        # Cache and return the result
        self.result_cache[email] = result
        return result
    
    def _verify_google_login(self, email: str) -> LoginVerificationResult:
        """Verify email existence using Google's login flow."""
        try:
            # Use requests to check initial response
            session = requests.Session()
            
            # Add headers to look like a browser
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Referer': 'https://www.google.com/',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            
            # First request to get cookies and initial form
            response = session.get('https://accounts.google.com/signin', headers=headers)
            
            # Now we need to use Selenium for the actual login attempt
            driver = webdriver.Chrome(options=self.chrome_options)
            
            try:
                # Navigate to login page
                driver.get('https://accounts.google.com/signin')
                
                # Wait for email field and enter email
                email_field = WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.ID, "identifierId"))
                )
                email_field.send_keys(email)
                
                # Click next
                next_button = driver.find_element(By.ID, "identifierNext")
                next_button.click()
                
                # Wait for either password field or error message
                time.sleep(2)  # Give it time to process
                
                # Check for error messages
                page_source = driver.page_source.lower()
                
                # Check for phrases indicating email doesn't exist
                for phrase in self.nonexistent_email_phrases['gmail.com'] + self.nonexistent_email_phrases['generic']:
                    if phrase.lower() in page_source:
                        return LoginVerificationResult(
                            email=email,
                            exists=False,
                            reason="Email address does not exist",
                            provider="Google",
                            details={"error_phrase": phrase}
                        )
                
                # Check for password field (indicates email exists)
                try:
                    WebDriverWait(driver, 5).until(
                        EC.presence_of_element_located((By.NAME, "password"))
                    )
                    return LoginVerificationResult(
                        email=email,
                        exists=True,
                        reason="Email address exists (password prompt appeared)",
                        provider="Google"
                    )
                except TimeoutException:
                    # If we can't find a clear indicator, assume it might exist
                    return LoginVerificationResult(
                        email=email,
                        exists=True,
                        reason="Email address likely exists (no clear rejection)",
                        provider="Google"
                    )
            
            finally:
                driver.quit()
        
        except Exception as e:
            logger.error(f"Error verifying Google login for {email}: {e}")
            return LoginVerificationResult(
                email=email,
                exists=False,
                reason=f"Verification error: {str(e)}",
                provider="Google"
            )
    
    def _verify_microsoft_login(self, email: str) -> LoginVerificationResult:
        """Verify email existence using Microsoft's login flow."""
        try:
            driver = webdriver.Chrome(options=self.chrome_options)
            
            try:
                # Navigate to login page
                driver.get('https://login.live.com')
                
                # Wait for email field and enter email
                email_field = WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.NAME, "loginfmt"))
                )
                email_field.send_keys(email)
                
                # Click next
                next_button = driver.find_element(By.ID, "idSIButton9")
                next_button.click()
                
                # Wait for either password field or error message
                time.sleep(2)  # Give it time to process
                
                # Check for error messages
                page_source = driver.page_source.lower()
                
                # Check for phrases indicating email doesn't exist
                for phrase in self.nonexistent_email_phrases['outlook.com'] + self.nonexistent_email_phrases['generic']:
                    if phrase.lower() in page_source:
                        return LoginVerificationResult(
                            email=email,
                            exists=False,
                            reason="Email address does not exist",
                            provider="Microsoft",
                            details={"error_phrase": phrase}
                        )
                
                # Check for password field (indicates email exists)
                try:
                    WebDriverWait(driver, 5).until(
                        EC.presence_of_element_located((By.NAME, "passwd"))
                    )
                    return LoginVerificationResult(
                        email=email,
                        exists=True,
                        reason="Email address exists (password prompt appeared)",
                        provider="Microsoft"
                    )
                except TimeoutException:
                    # If we can't find a clear indicator, assume it might exist
                    return LoginVerificationResult(
                        email=email,
                        exists=True,
                        reason="Email address likely exists (no clear rejection)",
                        provider="Microsoft"
                    )
            
            finally:
                driver.quit()
        
        except Exception as e:
            logger.error(f"Error verifying Microsoft login for {email}: {e}")
            return LoginVerificationResult(
                email=email,
                exists=False,
                reason=f"Verification error: {str(e)}",
                provider="Microsoft"
            )
    
    def _verify_yahoo_login(self, email: str) -> LoginVerificationResult:
        """Verify email existence using Yahoo's login flow."""
        try:
            driver = webdriver.Chrome(options=self.chrome_options)
            
            try:
                # Navigate to login page
                driver.get('https://login.yahoo.com')
                
                # Wait for email field and enter email
                email_field = WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.ID, "login-username"))
                )
                email_field.send_keys(email)
                
                # Click next
                next_button = driver.find_element(By.ID, "login-signin")
                next_button.click()
                
                # Wait for either password field or error message
                time.sleep(2)  # Give it time to process
                
                # Check for error messages
                page_source = driver.page_source.lower()
                
                # Check for phrases indicating email doesn't exist
                for phrase in self.nonexistent_email_phrases['yahoo.com'] + self.nonexistent_email_phrases['generic']:
                    if phrase.lower() in page_source:
                        return LoginVerificationResult(
                            email=email,
                            exists=False,
                            reason="Email address does not exist",
                            provider="Yahoo",
                            details={"error_phrase": phrase}
                        )
                
                # Check for password field (indicates email exists)
                try:
                    WebDriverWait(driver, 5).until(
                        EC.presence_of_element_located((By.ID, "login-passwd"))
                    )
                    return LoginVerificationResult(
                        email=email,
                        exists=True,
                        reason="Email address exists (password prompt appeared)",
                        provider="Yahoo"
                    )
                except TimeoutException:
                    # If we can't find a clear indicator, assume it might exist
                    return LoginVerificationResult(
                        email=email,
                        exists=True,
                        reason="Email address likely exists (no clear rejection)",
                        provider="Yahoo"
                    )
            
            finally:
                driver.quit()
        
        except Exception as e:
            logger.error(f"Error verifying Yahoo login for {email}: {e}")
            return LoginVerificationResult(
                email=email,
                exists=False,
                reason=f"Verification error: {str(e)}",
                provider="Yahoo"
            )
    
    def _verify_generic_login(self, email: str, login_url: str, provider: str) -> LoginVerificationResult:
        """Generic login verification for other providers."""
        try:
            driver = webdriver.Chrome(options=self.chrome_options)
            
            try:
                # Navigate to login page
                driver.get(login_url)
                
                # Look for common email input field patterns
                email_field = None
                for selector in [
                    "input[type='email']", 
                    "input[name='email']", 
                    "input[name='username']", 
                    "input[id*='email']", 
                    "input[id*='user']"
                ]:
                    try:
                        email_field = WebDriverWait(driver, 5).until(
                            EC.presence_of_element_located((By.CSS_SELECTOR, selector))
                        )
                        break
                    except TimeoutException:
                        continue
                
                if not email_field:
                    return LoginVerificationResult(
                        email=email,
                        exists=False,
                        reason="Could not find email input field",
                        provider=provider
                    )
                
                # Enter email
                email_field.send_keys(email)
                
                # Look for and click submit/next button
                button = None
                for selector in [
                    "button[type='submit']", 
                    "input[type='submit']", 
                    "button:contains('Next')", 
                    "button:contains('Continue')",
                    "button:contains('Sign in')"
                ]:
                    try:
                        button = driver.find_element(By.CSS_SELECTOR, selector)
                        break
                    except NoSuchElementException:
                        continue
                
                if button:
                    button.click()
                    
                    # Wait for response
                    time.sleep(3)
                    
                    # Check page source for error messages
                    page_source = driver.page_source.lower()
                    
                    # Check for phrases indicating email doesn't exist
                    for phrase in self.nonexistent_email_phrases['generic']:
                        if phrase.lower() in page_source:
                            return LoginVerificationResult(
                                email=email,
                                exists=False,
                                reason="Email address does not exist",
                                provider=provider,
                                details={"error_phrase": phrase}
                            )
                    
                    # Check for password field (indicates email exists)
                    try:
                        WebDriverWait(driver, 5).until(
                            EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='password']"))
                        )
                        return LoginVerificationResult(
                            email=email,
                            exists=True,
                            reason="Email address exists (password prompt appeared)",
                            provider=provider
                        )
                    except TimeoutException:
                        # If we can't find a clear indicator, assume it might exist
                        return LoginVerificationResult(
                            email=email,
                            exists=True,
                            reason="Email address likely exists (no clear rejection)",
                            provider=provider
                        )
                
                return LoginVerificationResult(
                    email=email,
                    exists=False,
                    reason="Could not complete login flow",
                    provider=provider
                )
            
            finally:
                driver.quit()
        
        except Exception as e:
            logger.error(f"Error verifying generic login for {email}: {e}")
            return LoginVerificationResult(
                email=email,
                exists=False,
                reason=f"Verification error: {str(e)}",
                provider=provider
            )
    
    def batch_verify(self, emails: List[str], max_parallel: int = 1) -> Dict[str, LoginVerificationResult]:
        """
        Verify multiple email addresses.
        Note: We limit parallelism to avoid getting blocked by providers.
        """
        results = {}
        
        for email in emails:
            results[email] = self.verify_email_login(email)
            # Add a significant delay between checks to avoid rate limiting
            time.sleep(random.uniform(3, 5))
        
        return results

# Example usage
if __name__ == "__main__":
    verifier = LoginEmailVerifier()
    
    # Test a single email
    email_to_test = input("Enter an email to verify: ")
    result = verifier.verify_email_login(email_to_test)
    
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