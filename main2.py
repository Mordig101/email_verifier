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
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.action_chains import ActionChains
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException, StaleElementReferenceException, ElementClickInterceptedException, ElementNotInteractableException

# Configure logging with more detailed format
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Email categories
VALID = "valid"
INVALID = "invalid"
RISKY = "risky"
CUSTOM = "custom"

# Create screenshots directory
SCREENSHOTS_DIR = "./screenshots"
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

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
        
        # Google-specific URL patterns for different states
        self.google_url_patterns = {
            'identifier': '/signin/identifier',  # Initial login page
            'pwd_challenge': '/signin/challenge/pwd',  # Password page (valid email)
            'rejected': '/signin/rejected',  # Security issue or rate limiting, not necessarily invalid
            'captcha': '/signin/v2/challenge/ipp',  # CAPTCHA challenge
            'security_challenge': '/signin/challenge',  # Other security challenges
        }
        
        # Provider-specific page changes that indicate valid emails
        self.valid_email_indicators = {
            'gmail.com': {
                'heading_changes': {
                    'before': ['Sign in'],
                    'after': ['Welcome']
                },
                'url_patterns': {
                    'before': '/signin/identifier',
                    'after': '/signin/challenge/pwd'
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
        
        # Initialize browser options
        self.chrome_options = Options()
        
        # Use incognito mode to avoid cookies and history
        self.chrome_options.add_argument("--incognito")
        
        # Other browser settings
        self.chrome_options.add_argument("--no-sandbox")
        self.chrome_options.add_argument("--disable-dev-shm-usage")
        self.chrome_options.add_argument("--disable-gpu")
        self.chrome_options.add_argument("--window-size=1920,1080")
        
        # Use a more realistic user agent
        self.chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")
        
        # Disable automation flags to avoid detection
        self.chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        self.chrome_options.add_experimental_option("useAutomationExtension", False)
        
        # Set preferences to disable saving passwords and autofill
        prefs = {
            "credentials_enable_service": False,
            "profile.password_manager_enabled": False,
            "autofill.profile_enabled": False,
            "autofill.credit_card_enabled": False
        }
        self.chrome_options.add_experimental_option("prefs", prefs)

        # Add the --enable-unsafe-swiftshader flag
        self.chrome_options.add_argument("--enable-unsafe-swiftshader")

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
        
        # Step 4: For custom domains without a known login URL, mark as custom
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
        
        # Step 5: Attempt login verification
        result = self._verify_login(email, provider, login_url)
        
        # Save result to cache and CSV
        self.result_cache[email] = result
        self.save_result(result)
        
        return result

    def take_screenshot(self, driver, email, stage):
        """Take a screenshot at a specific stage of the verification process."""
        try:
            filename = f"{SCREENSHOTS_DIR}/{email.replace('@', '_at_')}_{stage}.png"
            driver.save_screenshot(filename)
            logger.info(f"Screenshot saved: {filename}")
            return filename
        except Exception as e:
            logger.error(f"Error taking screenshot: {e}")
            return None

    def human_like_typing(self, element, text):
        """Type text in a human-like manner with random delays between keystrokes."""
        for char in text:
            element.send_keys(char)
            # Random delay between keystrokes (50-200ms)
            time.sleep(random.uniform(0.05, 0.2))

    def human_like_move_and_click(self, driver, element):
        """Move to an element and click it in a human-like manner."""
        try:
            # Create action chain
            actions = ActionChains(driver)
            
            # Move to a random position first
            viewport_width = driver.execute_script("return window.innerWidth;")
            viewport_height = driver.execute_script("return window.innerHeight;")
            random_x = random.randint(0, viewport_width)
            random_y = random.randint(0, viewport_height)
            
            # Move to random position, then to element with a slight offset, then click
            actions.move_by_offset(random_x, random_y)
            actions.pause(random.uniform(0.1, 0.3))
            
            # Get element location
            element_x = element.location['x']
            element_y = element.location['y']
            
            # Calculate center of element
            element_width = element.size['width']
            element_height = element.size['height']
            center_x = element_x + element_width / 2
            center_y = element_y + element_height / 2
            
            # Move to element with slight random offset
            offset_x = random.uniform(-5, 5)
            offset_y = random.uniform(-5, 5)
            actions.move_to_element_with_offset(element, offset_x, offset_y)
            actions.pause(random.uniform(0.1, 0.3))
            
            # Click
            actions.click()
            actions.perform()
            
            return True
        except Exception as e:
            logger.warning(f"Human-like click failed: {e}")
            # Fall back to regular click
            try:
                element.click()
                return True
            except Exception as click_e:
                logger.error(f"Regular click also failed: {click_e}")
                # Last resort: JavaScript click
                try:
                    driver.execute_script("arguments[0].click();", element)
                    return True
                except Exception as js_e:
                    logger.error(f"JavaScript click failed: {js_e}")
                    return False

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
        This improved version checks for hidden password fields, page heading changes,
        and URL changes for Google login.
        """
        # Check for URL changes that indicate a valid email (Google specific)
        if provider in ['gmail.com', 'googlemail.com']:
            current_url = driver.current_url
            # Check if URL changed to the password challenge URL
            if '/signin/challenge/pwd' in current_url:
                return True, "URL changed to password challenge"
        
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

    def check_for_captcha(self, driver):
        """
        Check if the page contains a CAPTCHA challenge.
        Returns True if a CAPTCHA is found, False otherwise.
        """
        try:
            # Check for CAPTCHA image
            captcha_img = driver.find_elements(By.ID, "captchaimg")
            if captcha_img and any(img.is_displayed() for img in captcha_img):
                return True, "CAPTCHA image found"
            
            # Check for reCAPTCHA
            recaptcha = driver.find_elements(By.CSS_SELECTOR, ".g-recaptcha, iframe[src*='recaptcha']")
            if recaptcha and any(elem.is_displayed() for elem in recaptcha):
                return True, "reCAPTCHA found"
            
            # Check for CAPTCHA in URL
            if '/challenge/ipp' in driver.current_url or 'captcha' in driver.current_url.lower():
                return True, "CAPTCHA challenge in URL"
            
            # Check for CAPTCHA text input
            captcha_input = driver.find_elements(By.CSS_SELECTOR, "input[name='ca'], input[id='ca']")
            if captcha_input and any(input_field.is_displayed() for input_field in captcha_input):
                return True, "CAPTCHA input field found"
            
            return False, None
        except Exception as e:
            logger.error(f"Error checking for CAPTCHA: {e}")
            return False, None

    def analyze_google_url(self, url, page_source=None):
        """
        Analyze Google URL to determine the state of the login process.
        Returns a tuple of (state, details)
        """
        # Check for different URL patterns
        if self.google_url_patterns['pwd_challenge'] in url:
            return "valid", "URL indicates password challenge (valid email)"
        elif self.google_url_patterns['rejected'] in url:
            # Rejected URL doesn't necessarily mean invalid email
            # It could be a security measure or rate limiting
            return "rejected", "URL indicates rejected login attempt (security measure)"
        elif self.google_url_patterns['captcha'] in url or 'captcha' in url.lower():
            return "captcha", "URL indicates CAPTCHA challenge"
        elif self.google_url_patterns['security_challenge'] in url:
            return "security", "URL indicates security challenge"
        elif self.google_url_patterns['identifier'] in url:
            # Check if we're still on the identifier page but with an error message
            if page_source and any(phrase.lower() in page_source.lower() for phrase in self.nonexistent_email_phrases['gmail.com']):
                return "invalid", "Error message indicates invalid email"
            return "initial", "Still on identifier page"
        else:
            return "unknown", f"Unknown URL pattern: {url}"

    def _verify_google_email(self, driver, email, initial_url, before_heading):
        """
        Special verification method for Google emails.
        """
        # Get the current URL after clicking next
        current_url = driver.current_url
        logger.info(f"URL after clicking next: {current_url}")
        
        # Take screenshot after clicking next
        self.take_screenshot(driver, email, "after_next")
        
        # Check for CAPTCHA first
        has_captcha, captcha_reason = self.check_for_captcha(driver)
        if has_captcha:
            logger.warning(f"CAPTCHA detected for {email}: {captcha_reason}")
            return EmailVerificationResult(
                email=email,
                category=RISKY,
                reason=f"CAPTCHA challenge encountered: {captcha_reason}",
                provider="gmail.com",
                details={"current_url": current_url}
            )
        
        # Get page source for error checking
        page_source = driver.page_source
        
        # Analyze Google URL to determine state
        state, details = self.analyze_google_url(current_url, page_source)
        logger.info(f"Google URL analysis: {state} - {details}")
        
        if state == "valid":
            return EmailVerificationResult(
                email=email,
                category=VALID,
                reason=f"Email address exists ({details})",
                provider="gmail.com",
                details={"initial_url": initial_url, "current_url": current_url}
            )
        elif state == "invalid":
            return EmailVerificationResult(
                email=email,
                category=INVALID,
                reason=f"Email address does not exist ({details})",
                provider="gmail.com",
                details={"initial_url": initial_url, "current_url": current_url}
            )
        elif state == "rejected":
            # For rejected URLs, we need to check if there's an error message
            # indicating the email doesn't exist
            has_error, error_phrase = self.check_for_error_message(driver, "gmail.com")
            if has_error:
                return EmailVerificationResult(
                    email=email,
                    category=INVALID,
                    reason=f"Email address does not exist ({error_phrase})",
                    provider="gmail.com",
                    details={"error_phrase": error_phrase, "current_url": current_url}
                )
            
            # If no clear error message, check for password field
            has_password, password_reason = self.check_for_password_field(driver, "gmail.com", before_heading)
            if has_password:
                return EmailVerificationResult(
                    email=email,
                    category=VALID,
                    reason=f"Email address exists ({password_reason})",
                    provider="gmail.com",
                    details={"current_url": current_url}
                )
            
            # If we can't determine, mark as risky
            return EmailVerificationResult(
                email=email,
                category=RISKY,
                reason=f"Rejected login but could not determine if email exists",
                provider="gmail.com",
                details={"current_url": current_url}
            )
        elif state == "captcha":
            return EmailVerificationResult(
                email=email,
                category=RISKY,
                reason=f"CAPTCHA challenge encountered ({details})",
                provider="gmail.com",
                details={"initial_url": initial_url, "current_url": current_url}
            )
        elif state == "security":
            # If we hit a security challenge, the email likely exists
            return EmailVerificationResult(
                email=email,
                category=VALID,
                reason=f"Email likely exists (security challenge)",
                provider="gmail.com",
                details={"initial_url": initial_url, "current_url": current_url}
            )
        elif state == "initial":
            # Still on the identifier page, check for error messages
            has_error, error_phrase = self.check_for_error_message(driver, "gmail.com")
            if has_error:
                return EmailVerificationResult(
                    email=email,
                    category=INVALID,
                    reason=f"Email address does not exist ({error_phrase})",
                    provider="gmail.com",
                    details={"error_phrase": error_phrase}
                )
            else:
                # No error message but still on identifier page - might be a UI issue
                return EmailVerificationResult(
                    email=email,
                    category=RISKY,
                    reason="Could not proceed past identifier page (no error message)",
                    provider="gmail.com",
                    details={"current_url": current_url}
                )
        else:  # Unknown state
            # Check if we can find a password field anyway
            has_password, password_reason = self.check_for_password_field(driver, "gmail.com", before_heading)
            if has_password:
                return EmailVerificationResult(
                    email=email,
                    category=VALID,
                    reason=f"Email address exists ({password_reason})",
                    provider="gmail.com",
                    details={"initial_url": initial_url, "current_url": current_url}
                )
            
            # Check for error messages
            has_error, error_phrase = self.check_for_error_message(driver, "gmail.com")
            if has_error:
                return EmailVerificationResult(
                    email=email,
                    category=INVALID,
                    reason=f"Email address does not exist ({error_phrase})",
                    provider="gmail.com",
                    details={"error_phrase": error_phrase}
                )
            
            # If we can't determine, mark as risky
            return EmailVerificationResult(
                email=email,
                category=RISKY,
                reason=f"Unknown Google login state: {details}",
                provider="gmail.com",
                details={"initial_url": initial_url, "current_url": current_url}
            )

    def _verify_login(self, email: str, provider: str, login_url: str) -> EmailVerificationResult:
        """
        Verify email by attempting to log in and analyzing the response.
        """
        driver = None
        try:
            # Initialize the browser
            driver = webdriver.Chrome(options=self.chrome_options)
            
            # Add random delay before navigating (1-3 seconds)
            time.sleep(random.uniform(1, 3))
            
            # Navigate to login page
            logger.info(f"Navigating to login page: {login_url}")
            driver.get(login_url)
            
            # Wait for page to load with random delay (2-4 seconds)
            time.sleep(random.uniform(2, 4))
            
            # Store the initial URL for comparison later
            initial_url = driver.current_url
            logger.info(f"Initial URL: {initial_url}")
            
            # Get the initial page heading
            before_heading = self.get_page_heading(driver)
            logger.info(f"Initial page heading: {before_heading}")
            
            # Take screenshot before entering email
            self.take_screenshot(driver, email, "before_email")
            
            # Find email input field
            email_field = self.find_email_field(driver)
            
            if not email_field:
                logger.warning(f"Could not find email input field for {email}")
                # If we can't find the email field, it might be a custom login page
                return EmailVerificationResult(
                    email=email,
                    category=CUSTOM,
                    reason="Could not find email input field on login page",
                    provider=provider,
                    details={"current_url": driver.current_url}
                )
            
            # Enter email with human-like typing
            logger.info(f"Entering email: {email}")
            self.human_like_typing(email_field, email)
            
            # Random delay after typing (0.5-1.5 seconds)
            time.sleep(random.uniform(0.5, 1.5))
            
            # Find next button
            next_button = self.find_next_button(driver)
            
            if not next_button:
                logger.warning(f"Could not find next button for {email}")
                # If we can't find the next button, it might be a custom login page
                return EmailVerificationResult(
                    email=email,
                    category=CUSTOM,
                    reason="Could not find next/submit button on login page",
                    provider=provider,
                    details={"current_url": driver.current_url}
                )
            
            # Take screenshot before clicking next
            self.take_screenshot(driver, email, "before_next")
            
            # Try to click next button with human-like movement
            logger.info("Clicking next button")
            click_success = self.human_like_move_and_click(driver, next_button)
            
            if not click_success:
                logger.error("All click methods failed")
                return EmailVerificationResult(
                    email=email,
                    category=RISKY,
                    reason="Could not click next button after multiple attempts",
                    provider=provider,
                    details={"current_url": driver.current_url}
                )
            
            # Wait for response with random delay (2-4 seconds)
            time.sleep(random.uniform(2, 4))
            
            # Special handling for Google emails
            if provider in ['gmail.com', 'googlemail.com']:
                return self._verify_google_email(driver, email, initial_url, before_heading)
            
            # For non-Google providers, continue with the original logic
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
            
            # Check if we were redirected to a custom domain login
            original_domain = login_url.split('/')[2]
            current_domain = driver.current_url.split('/')[2]
            
            # If we're redirected to a different domain, it might be a custom login
            if original_domain != current_domain and "login" in driver.current_url.lower():
                # Try to find password field on the new page
                has_password, password_reason = self.check_for_password_field(driver, provider, before_heading)
                if has_password:
                    return EmailVerificationResult(
                        email=email,
                        category=VALID,
                        reason=f"Email address exists ({password_reason} after redirect)",
                        provider=provider,
                        details={"redirect_url": driver.current_url}
                    )
                
                # If we can't determine, mark as custom
                return EmailVerificationResult(
                    email=email,
                    category=CUSTOM,
                    reason="Redirected to custom login page",
                    provider=provider,
                    details={"redirect_url": driver.current_url}
                )
            
            # If we can't find a password field or error message, check if we're still on the same page
            if login_url.split('?')[0] in driver.current_url.split('?')[0]:
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
                # Try one more time to check for password field
                has_password, password_reason = self.check_for_password_field(driver, provider, before_heading)
                if has_password:
                    return EmailVerificationResult(
                        email=email,
                        category=VALID,
                        reason=f"Email address exists ({password_reason} after redirect)",
                        provider=provider,
                        details={"redirect_url": driver.current_url}
                    )
                
                # If still no password field, mark as custom
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