import re
import csv
import os
import dns.resolver
import logging
import time
import random
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Email categories
VALID = "valid"
INVALID = "invalid"
RISKY = "risky"
CUSTOM = "custom"

@dataclass
class EmailVerificationResult:
    email: str
    category: str  # valid, invalid, risky, custom
    reason: str
    provider: str
    details: Optional[Dict[str, Any]] = None
    
    def __str__(self) -> str:
        return f"{self.email}: {self.category} ({self.provider}) - {self.reason}"

class LoginEmailVerifier:
    def __init__(self, output_dir="./results"):
        # Create output directory if it doesn't exist
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize CSV files
        self.csv_files = {
            VALID: os.path.join(output_dir, "valid_emails.csv"),
            INVALID: os.path.join(output_dir, "invalid_emails.csv"),
            RISKY: os.path.join(output_dir, "risky_emails.csv"),
            CUSTOM: os.path.join(output_dir, "custom_emails.csv"),
        }
        
        # Create CSV files with headers if they don't exist
        for category, file_path in self.csv_files.items():
            if not os.path.exists(file_path):
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Email", "Provider", "Reason", "Details"])
        
        # Cache for verification results
        self.result_cache: Dict[str, EmailVerificationResult] = {}
        
        # Known email providers and their login URLs
        self.provider_login_urls = {
            # Major providers
            'gmail.com': 'https://accounts.google.com/signin',
            'googlemail.com': 'https://accounts.google.com/signin',
            'outlook.com': 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?scope=service%3A%3Aaccount.microsoft.com%3A%3AMBI_SSL+openid+profile+offline_access&response_type=code&client_id=81feaced-5ddd-41e7-8bef-3e20a2689bb7&redirect_uri=https%3A%2F%2Faccount.microsoft.com%2Fauth%2Fcomplete-signin-oauth&client-request-id=a5edf688-de60-4159-ac1a-6051cad1dbf6&x-client-SKU=MSAL.Desktop&x-client-Ver=4.66.1.0&x-client-OS=Windows+Server+2019+Datacenter&prompt=login&client_info=1&state=H4sIAAAAAAAEAAXBS4JDMAAA0Lt0ayEdv7HUjk810oRQ6U5JNRgaaorTz3u7QFbcpEJKJU_BS_9gdke_j4OJnMT31ORrjXjW9QvOaIyxbqxpyCGO2KVuJy3uwJa-UPUYmz81vs9WebdvUM8QlZ04kvEzLZCnDBrxNzMksSvArSdefYxdjJAUBXFgxPXSe4tR3T-1JRB-vi87GtvujG7wbHq9VA4emHLkpK4eGUDAvLjS4ZKhp7LSbcJBO7GReMqxGJwwDnAzeGpYd_INH83bI5iSnhWIJrlQrEUrr93544K_JTxlzflAhPWqooidyhawPUPL1LnoWreR7iqm0rfVTTPJYG6cjHCgmw9r2wFzvlqJ83MKoOBzuvsHQbnLUkIBAAA&msaoauth2=true&lc=1036',
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
        
        # If we can't identify the provider, it's a custom domain
        return 'custom', None
    
    def save_result(self, result: EmailVerificationResult):
        """Save verification result to the appropriate CSV file."""
        file_path = self.csv_files[result.category]
        
        # Convert details to string if present
        details_str = str(result.details) if result.details else ""
        
        with open(file_path, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([result.email, result.provider, result.reason, details_str])
        
        logger.info(f"Saved {result.email} to {result.category} list")
    
    def verify_email(self, email: str) -> EmailVerificationResult:
        """
        Verify if an email exists by checking MX records and attempting to log in.
        """
        # Check cache first
        if email in self.result_cache:
            return self.result_cache[email]
        
        # Step 1: Validate email format
        if not self.validate_format(email):
            result = EmailVerificationResult(
                email=email,
                category=INVALID,
                reason="Invalid email format",
                provider="unknown"
            )
            self.result_cache[email] = result
            self.save_result(result)
            return result
        
        # Step 2: Check MX records
        _, domain = email.split('@')
        mx_records = self.get_mx_records(domain)
        
        if not mx_records:
            result = EmailVerificationResult(
                email=email,
                category=INVALID,
                reason="Domain has no mail servers",
                provider="unknown"
            )
            self.result_cache[email] = result
            self.save_result(result)
            return result
        
        # Step 3: Identify the provider
        provider, login_url = self.identify_provider(email)
        
        # Step 4: Skip verification for Gmail (assume valid as per user's request)
        if provider == 'gmail.com' or provider == 'googlemail.com':
            result = EmailVerificationResult(
                email=email,
                category=VALID,
                reason="Gmail account (assumed valid)",
                provider="Google"
            )
            self.result_cache[email] = result
            self.save_result(result)
            return result
        
        # Step 5: For custom domains without a known login URL, mark as custom
        if provider == 'custom' or not login_url:
            result = EmailVerificationResult(
                email=email,
                category=CUSTOM,
                reason="Custom domain with unknown login page",
                provider="Custom",
                details={"mx_records": mx_records}
            )
            self.result_cache[email] = result
            self.save_result(result)
            return result
        
        # Step 6: Attempt login verification
        result = self._verify_login(email, provider, login_url)
        
        # Save result to cache and CSV
        self.result_cache[email] = result
        self.save_result(result)
        
        return result
    
    def _verify_login(self, email: str, provider: str, login_url: str) -> EmailVerificationResult:
        """
        Verify email by attempting to log in and analyzing the response.
        """
        driver = None
        try:
            # Initialize the browser
            driver = webdriver.Chrome(options=self.chrome_options)
            
            # Navigate to login page
            driver.get(login_url)
            
            # Wait for page to load
            time.sleep(2)
            
            # Find email input field
            email_field = None
            for selector in [
                "input[type='email']", 
                "input[name='email']", 
                "input[name='username']", 
                "input[id*='email']", 
                "input[id*='user']",
                "input[id='identifierId']",  # Google
                "input[name='loginfmt']"     # Microsoft
            ]:
                try:
                    email_field = WebDriverWait(driver, 5).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, selector))
                    )
                    break
                except TimeoutException:
                    continue
            
            if not email_field:
                # If we can't find the email field, it might be a custom login page
                return EmailVerificationResult(
                    email=email,
                    category=CUSTOM,
                    reason="Could not find email input field on login page",
                    provider=provider,
                    details={"current_url": driver.current_url}
                )
            
            # Enter email
            email_field.clear()
            email_field.send_keys(email)
            
            # Find and click next/submit button
            next_button = None
            for selector in [
                "button[type='submit']",
                "input[type='submit']",
                "#identifierNext",  # Google
                "#idSIButton9",     # Microsoft
                "#login-signin"     # Yahoo
            ]:
                try:
                    next_button = driver.find_element(By.CSS_SELECTOR, selector)
                    break
                except NoSuchElementException:
                    continue
            
            if not next_button:
                # If we can't find the next button, it might be a custom login page
                return EmailVerificationResult(
                    email=email,
                    category=CUSTOM,
                    reason="Could not find next/submit button on login page",
                    provider=provider,
                    details={"current_url": driver.current_url}
                )
            
            # Click next button
            next_button.click()
            
            # Wait for response
            time.sleep(3)
            
            # Check if URL changed to a custom domain login
            current_url = driver.current_url
            if login_url not in current_url and "login" in current_url.lower():
                return EmailVerificationResult(
                    email=email,
                    category=CUSTOM,
                    reason="Redirected to custom login page",
                    provider=provider,
                    details={"redirect_url": current_url}
                )
            
            # Check for error messages
            page_source = driver.page_source.lower()
            
            # Check for phrases indicating email doesn't exist
            nonexistent_phrases = self.nonexistent_email_phrases.get(provider, []) + self.nonexistent_email_phrases['generic']
            for phrase in nonexistent_phrases:
                if phrase.lower() in page_source:
                    return EmailVerificationResult(
                        email=email,
                        category=INVALID,
                        reason="Email address does not exist",
                        provider=provider,
                        details={"error_phrase": phrase}
                    )
            
            # Check for password field (indicates email exists)
            try:
                WebDriverWait(driver, 5).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, "input[aria-disabled='false']"))
                )
                return EmailVerificationResult(
                    email=email,
                    category=VALID,
                    reason="Email address exists (password prompt appeared)",
                    provider=provider
                )
            except TimeoutException:
                # If we can't find a password field, check if we're still on the same page
                if login_url in driver.current_url:
                    # We're still on the login page, but no clear error message
                    # This is risky - might exist but we can't confirm
                    return EmailVerificationResult(
                        email=email,
                        category=RISKY,
                        reason="Could not determine if email exists (no password prompt or error)",
                        provider=provider,
                        details={"current_url": driver.current_url}
                    )
                else:
                    # We were redirected somewhere else
                    return EmailVerificationResult(
                        email=email,
                        category=CUSTOM,
                        reason="Redirected to another page",
                        provider=provider,
                        details={"redirect_url": driver.current_url}
                    )
        
        except WebDriverException as e:
            logger.error(f"Browser error verifying {email}: {e}")
            return EmailVerificationResult(
                email=email,
                category=RISKY,
                reason=f"Browser error: {str(e)}",
                provider=provider
            )
        
        except Exception as e:
            logger.error(f"Error verifying {email}: {e}")
            return EmailVerificationResult(
                email=email,
                category=RISKY,
                reason=f"Verification error: {str(e)}",
                provider=provider
            )
        
        finally:
            # Close the browser
            if driver:
                driver.quit()
    
    def batch_verify(self, emails: List[str]) -> Dict[str, EmailVerificationResult]:
        """
        Verify multiple email addresses.
        """
        results = {}
        
        for email in emails:
            results[email] = self.verify_email(email)
            # Add a delay between checks to avoid rate limiting
            time.sleep(random.uniform(2, 4))
        
        return results
    
    def get_results_summary(self) -> Dict[str, int]:
        """Get a summary of verification results."""
        counts = {
            VALID: 0,
            INVALID: 0,
            RISKY: 0,
            CUSTOM: 0
        }
        
        # Count from CSV files
        for category, file_path in self.csv_files.items():
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    # Subtract 1 for the header row
                    counts[category] = sum(1 for _ in f) - 1
        
        return counts

# Example usage
if __name__ == "__main__":
    verifier = LoginEmailVerifier()
    
    print("Email Verification Tool")
    print("======================")
    print("1. Verify a single email")
    print("2. Verify multiple emails")
    print("3. Show results summary")
    print("4. Exit")
    
    choice = input("\nEnter your choice (1-4): ")
    
    if choice == "1":
        email = input("Enter an email to verify: ")
        print(f"\nVerifying {email}...")
        result = verifier.verify_email(email)
        print(f"\nResult: {result}")
        if result.details:
            print(f"Details: {result.details}")
    
    elif choice == "2":
        input_method = input("Enter 'F' to load from file or 'M' to enter manually: ").upper()
        
        if input_method == "F":
            file_path = input("Enter the path to the file (one email per line): ")
            try:
                with open(file_path, 'r') as f:
                    emails = [line.strip() for line in f if line.strip()]
                
                print(f"\nVerifying {len(emails)} emails...")
                for i, email in enumerate(emails, 1):
                    print(f"[{i}/{len(emails)}] Verifying {email}...")
                    result = verifier.verify_email(email)
                    print(f"  Result: {result.category} - {result.reason}")
            
            except Exception as e:
                print(f"Error reading file: {e}")
        
        else:
            emails_input = input("Enter emails separated by commas: ")
            emails = [email.strip() for email in emails_input.split(",") if email.strip()]
            
            print(f"\nVerifying {len(emails)} emails...")
            for i, email in enumerate(emails, 1):
                print(f"[{i}/{len(emails)}] Verifying {email}...")
                result = verifier.verify_email(email)
                print(f"  Result: {result.category} - {result.reason}")
    
    elif choice == "3":
        summary = verifier.get_results_summary()
        print("\nResults Summary:")
        print(f"Valid emails: {summary[VALID]}")
        print(f"Invalid emails: {summary[INVALID]}")
        print(f"Risky emails: {summary[RISKY]}")
        print(f"Custom domain emails: {summary[CUSTOM]}")
        print(f"\nTotal: {sum(summary.values())}")
        
        print("\nResults are saved in the following files:")
        for category, file_path in verifier.csv_files.items():
            print(f"{category.capitalize()} emails: {file_path}")
    
    else:
        print("Exiting...")