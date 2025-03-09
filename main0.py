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
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException, StaleElementReferenceException

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

class ImprovedLoginVerifier:
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
        
        # Cache for catch-all domain results
        self.catchall_domain_cache: Dict[str, bool] = {}
        
        # Known email providers and their login URLs
        self.provider_login_urls = {
            # Major providers
            'gmail.com': 'https://accounts.google.com/v3/signin/identifier?checkedDomains=youtube&continue=https%3A%2F%2Faccounts.google.com%2F&ddm=1&flowEntry=ServiceLogin&flowName=GlifWebSignIn&followup=https%3A%2F%2Faccounts.google.com%2F&ifkv=ASSHykqZwmsZ-Y8kMUy1FaZIF_roUjdswunM1zU1MHwMol0ScsWw6Ccfrnl6CF5AGNdJYnPIXWCAag&pstMsg=1&dsh=S-618504277%3A1741397881564214',
            'googlemail.com': 'https://accounts.google.com/v3/signin/identifier?flowName=GlifWebSignIn',
            'outlook.com': 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?scope=service%3A%3Aaccount.microsoft.com%3A%3AMBI_SSL+openid+profile+offline_access&response_type=code&client_id=81feaced-5ddd-41e7-8bef-3e20a2689bb7&redirect_uri=https%3A%2F%2Faccount.microsoft.com%2Fauth%2Fcomplete-signin-oauth&client-request-id=91a4ca34-664d-4f85-b023-b815182d057e&x-client-SKU=MSAL.Desktop&x-client-Ver=4.66.1.0&x-client-OS=Windows+Server+2019+Datacenter&prompt=login&client_info=1&state=H4sIAAAAAAAEAA3OR4KCMAAAwL945QBoKB48gAhGTUKVcpOyUgIIIlnz-t15wWxOkdgndzKKgzSP0sPvj6ylebkaJnlzK-s0zslzEDxJW0UhHvEoa8gondYS2LTTFj8N67QGK0Xnl7SoUWRXezriNbboRIRAH11HDqhyTBouvKsZMdgD_EwXpH2sZhExKJfvafuKxXbvtGmo4JABCBsFdIXfz1A5ReoS5TaufobXzFD27PSPwvn1JjnTMNvUIxAhZIvJMrxonWBPzz_q-cwoGpZMT_dt0HJwoQjGbICKmRvY9fjN_a9X83yN15D0QONFuUsucuoQrfbvd--XVEViWqUbRJXAOukcyRNmjUoyrhYWNEAvdQbMsp2XArl4F9vEzh95s3fGb2Q-Hs2VHQ6bP6JJZGZaAQAA&msaoauth2=true&lc=1036&sso_reload=true',
            'hotmail.com': 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?scope=service%3A%3Aaccount.microsoft.com%3A%3AMBI_SSL+openid+profile+offline_access&response_type=code&client_id=81feaced-5ddd-41e7-8bef-3e20a2689bb7&redirect_uri=https%3A%2F%2Faccount.microsoft.com%2Fauth%2Fcomplete-signin-oauth&client-request-id=91a4ca34-664d-4f85-b023-b815182d057e&x-client-SKU=MSAL.Desktop&x-client-Ver=4.66.1.0&x-client-OS=Windows+Server+2019+Datacenter&prompt=login&client_info=1&state=H4sIAAAAAAAEAA3OR4KCMAAAwL945QBoKB48gAhGTUKVcpOyUgIIIlnz-t15wWxOkdgndzKKgzSP0sPvj6ylebkaJnlzK-s0zslzEDxJW0UhHvEoa8gondYS2LTTFj8N67QGK0Xnl7SoUWRXezriNbboRIRAH11HDqhyTBouvKsZMdgD_EwXpH2sZhExKJfvafuKxXbvtGmo4JABCBsFdIXfz1A5ReoS5TaufobXzFD27PSPwvn1JjnTMNvUIxAhZIvJMrxonWBPzz_q-cwoGpZMT_dt0HJwoQjGbICKmRvY9fjN_a9X83yN15D0QONFuUsucuoQrfbvd--XVEViWqUbRJXAOukcyRNmjUoyrhYWNEAvdQbMsp2XArl4F9vEzh95s3fGb2Q-Hs2VHQ6bP6JJZGZaAQAA&msaoauth2=true&lc=1036&sso_reload=true',
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
        
        # Google provider domains
        self.google_provider_domains = [
            'gmail.com',
            'googlemail.com',
            # Add other Google provider domains if needed
        ]
        
        # Error messages that indicate an email doesn't exist
        self.nonexistent_email_phrases = {
            # Google
            'gmail.com': [
                "couldn't find your google account",
                "couldn't find your account",
                "no account found with that email",
                "couldn't find an account with that email"
            ],
            # Microsoft
            'outlook.com': [
                "we couldn't find an account with that username",
                "that microsoft account doesn't exist",
                "no account found",
                "this username may be incorrect",
                "ce nom d'utilisateur est peut-être incorrect"
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
        
        # Provider-specific page changes that indicate valid emails
        self.valid_email_indicators = {
            'gmail.com': {
                'heading_changes': {
                    'before': ['Sign in'],
                    'after': ['Welcome']
                }
            },
            'outlook.com': {
                'heading_changes': {
                    'before': ['Sign in', 'Se connecter'],
                    'after': ['Enter password', 'Entrez le mot de passe']
                }
            }
        }
        
        # Next button text in different languages
        self.next_button_texts = [
            "Next", "Suivant", "Continuer", "Continue", "Weiter", 
            "Siguiente", "Próximo", "Avanti", "Volgende", "Далее",
            "下一步", "次へ", "다음", "التالي", "Tiếp theo"
        ]
        
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

    def is_google_catchall_domain(self, domain: str) -> bool:
        """
        Check if a Google domain is a catch-all domain by testing with a clearly invalid email.
        Returns True if it's a catch-all domain, False otherwise.
        """
        # Check cache first
        if domain in self.catchall_domain_cache:
            return self.catchall_domain_cache[domain]
        
        # Skip standard gmail.com domain - it's not a catch-all
        if domain == 'gmail.com':
            self.catchall_domain_cache[domain] = False
            return False
        
        # Generate a random string that's very unlikely to be a valid email
        random_string = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=20))
        test_email = f"{random_string}@{domain}"
        
        driver = None
        try:
            # Initialize the browser
            driver = webdriver.Chrome(options=self.chrome_options)
            
            # Navigate to Google login page
            driver.get(self.provider_login_urls['gmail.com'])
            
            # Wait for page to load
            time.sleep(3)
            
            # Find email input field
            email_field = self.find_email_field(driver)
            if not email_field:
                # If we can't find the email field, assume it's not a catch-all
                self.catchall_domain_cache[domain] = False
                return False
            
            # Enter the test email
            email_field.clear()
            email_field.send_keys(test_email)
            
            # Find and click next button
            next_button = self.find_next_button(driver)
            if not next_button:
                # If we can't find the next button, assume it's not a catch-all
                self.catchall_domain_cache[domain] = False
                return False
            
            # Click next button
            next_button.click()
            
            # Wait for response
            time.sleep(3)
            
            # Check for error messages
            has_error, _ = self.check_for_error_message(driver, 'gmail.com')
            
            # If there's no error message for a clearly invalid email, it's a catch-all domain
            is_catchall = not has_error
            
            # Cache the result
            self.catchall_domain_cache[domain] = is_catchall
            
            return is_catchall
            
        except Exception as e:
            logger.error(f"Error checking if {domain} is a catch-all domain: {e}")
            # In case of error, assume it's not a catch-all to be safe
            self.catchall_domain_cache[domain] = False
            return False
            
        finally:
            # Close the browser
            if driver:
                driver.quit()

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
        
        # Step 4: Special handling for Google provider emails
        if provider == 'gmail.com' or any(domain.endswith(f"@{google_domain}") for google_domain in self.google_provider_domains):
            # Skip standard @gmail.com addresses
            if domain == 'gmail.com':
                result = EmailVerificationResult(
                    email=email,
                    category=CUSTOM,
                    reason="Standard Gmail address - skipped as requested",
                    provider=provider
                )
                self.result_cache[email] = result
                self.save_result(result)
                return result
            
            # Check if it's a Google catch-all domain
            if self.is_google_catchall_domain(domain):
                result = EmailVerificationResult(
                    email=email,
                    category=RISKY,
                    reason="Google catch-all domain detected",
                    provider=provider,
                    details={"is_catchall": True}
                )
                self.result_cache[email] = result
                self.save_result(result)
                return result
            else:
                # Not a catch-all domain, consider it valid
                result = EmailVerificationResult(
                    email=email,
                    category=VALID,
                    reason="Google non-catch-all domain - email considered valid",
                    provider=provider,
                    details={"is_catchall": False}
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
        
        # Step 6: Attempt login verification for non-Google providers
        result = self._verify_login(email, provider, login_url)
        
        # Save result to cache and CSV
        self.result_cache[email] = result
        self.save_result(result)
        
        return result

    def find_next_button(self, driver):
        """
        Find the 'Next' button using multiple strategies.
        Returns the button element if found, None otherwise.
        """
        # Strategy 1: Look for buttons with specific text
        for text in self.next_button_texts:
            try:
                # Try exact text match
                elements = driver.find_elements(By.XPATH, f"//button[contains(text(), '{text}')]")
                if elements:
                    return elements[0]
                
                # Try case-insensitive match
                elements = driver.find_elements(By.XPATH, f"//button[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{text.lower()}')]")
                if elements:
                    return elements[0]
                
                # Try with span inside button
                elements = driver.find_elements(By.XPATH, f"//button//span[contains(text(), '{text}')]/..")
                if elements:
                    return elements[0]
                
                # Try with input buttons
                elements = driver.find_elements(By.XPATH, f"//input[@type='submit' and contains(@value, '{text}')]")
                if elements:
                    return elements[0]
            except Exception:
                continue
        
        # Strategy 2: Look for common button IDs and classes
        for selector in [
            "#identifierNext",  # Google
            "#idSIButton9",     # Microsoft
            "#login-signin",    # Yahoo
            "button[type='submit']",
            "input[type='submit']",
            ".VfPpkd-LgbsSe-OWXEXe-k8QpJ",  # Google's Next button class
            ".win-button.button_primary"     # Microsoft's Next button class
        ]:
            try:
                elements = driver.find_elements(By.CSS_SELECTOR, selector)
                if elements:
                    return elements[0]
            except Exception:
                continue
        
        # Strategy 3: Look for any button or input that might be a submit button
        try:
            # Look for buttons with common attributes
            for attr in ["submit", "login", "next", "continue", "signin"]:
                elements = driver.find_elements(By.CSS_SELECTOR, f"button[id*='{attr}'], button[class*='{attr}'], button[name*='{attr}']")
                if elements:
                    return elements[0]
            
            # Look for any button as a last resort
            elements = driver.find_elements(By.TAG_NAME, "button")
            if elements:
                # Try to find a button that looks like a submit button (e.g., positioned at the bottom)
                for element in elements:
                    if element.is_displayed() and element.is_enabled():
                        return element
        except Exception:
            pass
        
        return None

    def find_email_field(self, driver):
        """
        Find the email input field using multiple strategies.
        Returns the field element if found, None otherwise.
        """
        # Try common selectors for email fields
        for selector in [
            "input[type='email']", 
            "input[name='email']", 
            "input[name='username']", 
            "input[id*='email']", 
            "input[id*='user']",
            "input[id='identifierId']",  # Google
            "input[name='loginfmt']",    # Microsoft
            "input[id='login-username']" # Yahoo
        ]:
            try:
                elements = driver.find_elements(By.CSS_SELECTOR, selector)
                if elements and elements[0].is_displayed():
                    return elements[0]
            except Exception:
                continue
        
        # Try to find any input field that might accept email
        try:
            inputs = driver.find_elements(By.TAG_NAME, "input")
            for input_field in inputs:
                try:
                    if input_field.is_displayed() and input_field.get_attribute("type") in ["text", "email"]:
                        return input_field
                except StaleElementReferenceException:
                    continue
        except Exception:
            pass
        
        return None

    def check_for_error_message(self, driver, provider):
        """
        Check if the page contains an error message indicating the email doesn't exist.
        Returns True if an error is found, False otherwise.
        """
        page_source = driver.page_source.lower()
        
        # Get provider-specific error phrases
        error_phrases = self.nonexistent_email_phrases.get(provider, []) + self.nonexistent_email_phrases['generic']
        
        # Check for each phrase
        for phrase in error_phrases:
            if phrase.lower() in page_source:
                return True, phrase
        
        # Check for specific error elements
        try:
            # Google error message
            google_error = driver.find_elements(By.XPATH, "//div[contains(@class, 'Ekjuhf') or contains(@class, 'o6cuMc')]")
            if google_error and any("couldn't find" in element.text.lower() for element in google_error if element.is_displayed()):
                return True, "Google account not found"
            
            # Microsoft error message
            microsoft_error = driver.find_elements(By.ID, "usernameError")
            if microsoft_error and any(element.is_displayed() for element in microsoft_error):
                return True, "Microsoft account not found"
        except Exception:
            pass
        
        return False, None

    def get_page_heading(self, driver):
        """Get the main heading of the page."""
        try:
            # Try common heading elements
            for selector in [
                "h1#headingText", # Google
                "div#loginHeader", # Microsoft
                "h1", 
                ".heading", 
                "[role='heading']"
            ]:
                elements = driver.find_elements(By.CSS_SELECTOR, selector)
                for element in elements:
                    if element.is_displayed() and element.text.strip():
                        return element.text.strip()
            
            return None
        except Exception:
            return None

    def check_for_password_field(self, driver, provider, before_heading=None):
        """
        Check if the page contains a visible password field, indicating the email exists.
        This improved version checks for hidden password fields and page heading changes.
        """
        # Check for heading changes that indicate a valid email
        if provider in self.valid_email_indicators and before_heading:
            after_heading = self.get_page_heading(driver)
            if after_heading:
                # Check if heading changed from sign-in to password/welcome
                if (before_heading.lower() in [h.lower() for h in self.valid_email_indicators[provider]['heading_changes']['before']] and
                    after_heading.lower() in [h.lower() for h in self.valid_email_indicators[provider]['heading_changes']['after']]):
                    return True, "Heading changed to password prompt"
        
        # Check for visible password fields
        try:
            # Find all password fields
            password_fields = driver.find_elements(By.CSS_SELECTOR, "input[type='password']")
            
            # Check if any password field is visible and not hidden
            for field in password_fields:
                try:
                    # Check if the field is displayed
                    if not field.is_displayed():
                        continue
                    
                    # Check for attributes that indicate a hidden field
                    aria_hidden = field.get_attribute("aria-hidden")
                    tabindex = field.get_attribute("tabindex")
                    class_name = field.get_attribute("class")
                    
                    # Skip fields that are explicitly hidden
                    if (aria_hidden == "true" or 
                        tabindex == "-1" or 
                        any(hidden_class in (class_name or "") for hidden_class in ["moveOffScreen", "Hvu6D", "hidden"])):
                        continue
                    
                    # This is a visible password field
                    return True, "Visible password field found"
                except StaleElementReferenceException:
                    continue
            
            # Check for password-related labels or text that indicate a password prompt
            password_labels = driver.find_elements(By.XPATH, "//label[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'password')]")
            if password_labels and any(label.is_displayed() for label in password_labels):
                return True, "Password label found"
            
            # For Microsoft specifically, check for the password form
            if provider in ['outlook.com', 'hotmail.com', 'live.com', 'microsoft.com', 'office365.com']:
                password_form = driver.find_elements(By.CSS_SELECTOR, "form[name='f1'][data-testid='passwordForm']")
                if password_form:
                    return True, "Password form found"
            
            return False, None
        except Exception as e:
            logger.error(f"Error checking for password field: {e}")
            return False, None

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
            time.sleep(3)
            
            # Get the initial page heading
            before_heading = self.get_page_heading(driver)
            
            # Find email input field
            email_field = self.find_email_field(driver)
            
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
            
            # Find and click next button
            next_button = self.find_next_button(driver)
            
            if not next_button:
                # If we can't find the next button, it might be a custom login page
                return EmailVerificationResult(
                    email=email,
                    category=CUSTOM,
                    reason="Could not find next/submit button on login page",
                    provider=provider,
                    details={"current_url": driver.current_url}
                )
            
            # Take a screenshot before clicking next (for debugging)
            # driver.save_screenshot(f"before_{email.replace('@', '_at_')}.png")
            
            # Click next button
            next_button.click()
            
            # Wait for response
            time.sleep(3)
            
            # Take a screenshot after clicking next (for debugging)
            # driver.save_screenshot(f"after_{email.replace('@', '_at_')}.png")
            
            # Check if we were redirected to a custom domain login
            current_url = driver.current_url
            original_domain = login_url.split('/')[2]
            current_domain = current_url.split('/')[2]
            
            # Check for error messages first
            has_error, error_phrase = self.check_for_error_message(driver, provider)
            if has_error:
                return EmailVerificationResult(
                    email=email,
                    category=INVALID,
                    reason="Email address does not exist",
                    provider=provider,
                    details={"error_phrase": error_phrase}
                )
            
            # Check for password field or heading changes
            has_password, password_reason = self.check_for_password_field(driver, provider, before_heading)
            if has_password:
                return EmailVerificationResult(
                    email=email,
                    category=VALID,
                    reason=f"Email address exists ({password_reason})",
                    provider=provider
                )
            
            # If we're redirected to a different domain, it might be a custom login
            if original_domain != current_domain and "login" in current_url.lower():
                # Try to find password field on the new page
                has_password, password_reason = self.check_for_password_field(driver, provider, before_heading)
                if has_password:
                    return EmailVerificationResult(
                        email=email,
                        category=VALID,
                        reason=f"Email address exists ({password_reason} after redirect)",
                        provider=provider,
                        details={"redirect_url": current_url}
                    )
                
                # If we can't determine, mark as custom
                return EmailVerificationResult(
                    email=email,
                    category=CUSTOM,
                    reason="Redirected to custom login page",
                    provider=provider,
                    details={"redirect_url": current_url}
                )
            
            # If we can't find a password field or error message, check if we're still on the same page
            if login_url.split('?')[0] in current_url.split('?')[0]:
                # We're still on the login page, but no clear error message
                # This is risky - might exist but we can't confirm
                return EmailVerificationResult(
                    email=email,
                    category=RISKY,
                    reason="Could not determine if email exists (no password prompt or error)",
                    provider=provider,
                    details={"current_url": current_url}
                )
            else:
                # We were redirected somewhere else
                # Try one more time to check for password field
                has_password, password_reason = self.check_for_password_field(driver, provider, before_heading)
                if has_password:
                    return EmailVerificationResult(
                        email=email,
                        category=VALID,
                        reason=f"Email address exists ({password_reason} after redirect)",
                        provider=provider,
                        details={"redirect_url": current_url}
                    )
                
                # If still no password field, mark as custom
                return EmailVerificationResult(
                    email=email,
                    category=CUSTOM,
                    reason="Redirected to another page",
                    provider=provider,
                    details={"redirect_url": current_url}
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
    verifier = ImprovedLoginVerifier()

    print("Improved Email Verification Tool")
    print("===============================")
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

