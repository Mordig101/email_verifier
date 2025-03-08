import re
import csv
import os
import socket
import smtplib
import dns.resolver
import logging
import time
import random
import requests
from urllib.parse import urlparse
from typing import Dict, List, Optional, Tuple, Any, Set
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
CATCH_ALL = "catch_all"

@dataclass
class CustomEmailResult:
    email: str
    category: str  # valid, invalid, risky, catch_all
    reason: str
    verification_method: str  # login, smtp, pattern
    confidence: float  # 0-1 scale
    details: Optional[Dict[str, Any]] = None
    
    def __str__(self) -> str:
        return f"{self.email}: {self.category} ({self.verification_method}, {self.confidence:.2f}) - {self.reason}"

class CustomDomainVerifier:
    def __init__(self, output_dir="./results"):
        # Create output directory if it doesn't exist
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize CSV files
        self.csv_files = {
            VALID: os.path.join(output_dir, "custom_valid_emails.csv"),
            INVALID: os.path.join(output_dir, "custom_invalid_emails.csv"),
            RISKY: os.path.join(output_dir, "custom_risky_emails.csv"),
            CATCH_ALL: os.path.join(output_dir, "catch_all_domains.csv"),
        }
        
        # Create CSV files with headers if they don't exist
        for category, file_path in self.csv_files.items():
            if not os.path.exists(file_path):
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    if category == CATCH_ALL:
                        writer.writerow(["Domain", "Type", "Reason", "Details"])
                    else:
                        writer.writerow(["Email", "Domain", "Method", "Confidence", "Reason", "Details"])
        
        # Cache for verification results
        self.result_cache: Dict[str, CustomEmailResult] = {}
        
        # Cache for domain login pages
        self.domain_login_pages: Dict[str, Optional[str]] = {}
        
        # Cache for catch-all domains
        self.catch_all_domains: Set[str] = set()
        self.not_catch_all_domains: Set[str] = set()
        
        # Load existing catch-all domains
        self._load_catch_all_domains()
        
        # Initialize headless browser options
        self.chrome_options = Options()
        self.chrome_options.add_argument("--headless")
        self.chrome_options.add_argument("--no-sandbox")
        self.chrome_options.add_argument("--disable-dev-shm-usage")
        self.chrome_options.add_argument("--disable-gpu")
        self.chrome_options.add_argument("--window-size=1920,1080")
        self.chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36")
        
        # Test emails for catch-all detection
        self.test_usernames = [
            "thisisafakeemail123456",
            "nonexistentuser987654",
            "testuser_doesnt_exist"
        ]
        
        # Common login page patterns
        self.login_page_patterns = [
            "login",
            "signin",
            "auth",
            "account",
            "webmail",
            "mail",
            "portal",
            "owa",  # Outlook Web Access
            "roundcube",
            "cpanel",
            "user"
        ]
    
    def _load_catch_all_domains(self):
        """Load existing catch-all domains from CSV."""
        if os.path.exists(self.csv_files[CATCH_ALL]):
            try:
                with open(self.csv_files[CATCH_ALL], 'r', encoding='utf-8') as f:
                    reader = csv.reader(f)
                    next(reader)  # Skip header
                    for row in reader:
                        if row and len(row) > 0:
                            domain = row[0]
                            self.catch_all_domains.add(domain)
            except Exception as e:
                logger.error(f"Error loading catch-all domains: {e}")
    
    def save_result(self, result: CustomEmailResult):
        """Save verification result to the appropriate CSV file."""
        if result.category == CATCH_ALL:
            # This shouldn't happen, but just in case
            logger.warning(f"Attempted to save email as catch-all: {result.email}")
            return
        
        file_path = self.csv_files[result.category]
        
        # Convert details to string if present
        details_str = str(result.details) if result.details else ""
        
        # Extract domain from email
        domain = result.email.split('@')[1]
        
        with open(file_path, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                result.email, 
                domain,
                result.verification_method,
                result.confidence,
                result.reason, 
                details_str
            ])
        
        logger.info(f"Saved {result.email} to {result.category} list")
    
    def save_catch_all_domain(self, domain: str, catch_all_type: str, reason: str, details: Optional[Dict] = None):
        """Save a catch-all domain to the CSV file."""
        file_path = self.csv_files[CATCH_ALL]
        
        # Convert details to string if present
        details_str = str(details) if details else ""
        
        with open(file_path, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([domain, catch_all_type, reason, details_str])
        
        logger.info(f"Saved catch-all domain: {domain} ({catch_all_type})")
        
        # Add to cache
        self.catch_all_domains.add(domain)
    
    def validate_format(self, email: str) -> bool:
        """Check if the email has a valid format."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def get_mx_records(self, domain: str) -> List[str]:
        """Get MX records for a domain."""
        try:
            records = dns.resolver.resolve(domain, 'MX', lifetime=5)
            mx_servers = [str(x.exchange).rstrip('.').lower() for x in records]
            return mx_servers
        except Exception as e:
            logger.warning(f"Error getting MX records for {domain}: {e}")
            return []
    
    def find_login_page(self, domain: str) -> Optional[str]:
        """
        Find a login page for the domain using common patterns.
        Returns the URL if found, None otherwise.
        """
        # Check cache first
        if domain in self.domain_login_pages:
            return self.domain_login_pages[domain]
        
        login_url = None
        
        # Try common login page patterns
        for pattern in self.login_page_patterns:
            # Try HTTPS first
            url = f"https://{pattern}.{domain}"
            try:
                response = requests.head(url, timeout=5, allow_redirects=True)
                if response.status_code == 200:
                    login_url = url
                    break
            except:
                pass
            
            # Try HTTP if HTTPS fails
            url = f"http://{pattern}.{domain}"
            try:
                response = requests.head(url, timeout=5, allow_redirects=True)
                if response.status_code == 200:
                    login_url = url
                    break
            except:
                pass
            
            # Try subdirectory
            url = f"https://{domain}/{pattern}"
            try:
                response = requests.head(url, timeout=5, allow_redirects=True)
                if response.status_code == 200:
                    login_url = url
                    break
            except:
                pass
        
        # If no login page found with patterns, try the domain itself
        if not login_url:
            # Try HTTPS
            url = f"https://{domain}"
            try:
                response = requests.get(url, timeout=5, allow_redirects=True)
                # Check if the page contains login-related keywords
                if response.status_code == 200:
                    text = response.text.lower()
                    if any(keyword in text for keyword in ["login", "sign in", "username", "password", "email", "account"]):
                        login_url = url
            except:
                pass
            
            # Try HTTP if HTTPS fails
            if not login_url:
                url = f"http://{domain}"
                try:
                    response = requests.get(url, timeout=5, allow_redirects=True)
                    # Check if the page contains login-related keywords
                    if response.status_code == 200:
                        text = response.text.lower()
                        if any(keyword in text for keyword in ["login", "sign in", "username", "password", "email", "account"]):
                            login_url = url
                except:
                    pass
        
        # Cache the result
        self.domain_login_pages[domain] = login_url
        
        return login_url
    
    def is_catch_all_domain(self, domain: str) -> Tuple[bool, str, str]:
        """
        Check if a domain is a catch-all domain.
        Returns (is_catch_all, catch_all_type, reason)
        """
        # Check cache first
        if domain in self.catch_all_domains:
            return True, "unknown", "Previously identified as catch-all"
        
        if domain in self.not_catch_all_domains:
            return False, "", "Previously identified as not catch-all"
        
        # Get MX records
        mx_records = self.get_mx_records(domain)
        if not mx_records:
            return False, "", "No MX records"
        
        # Generate test emails
        test_emails = [f"{username}@{domain}" for username in self.test_usernames]
        
        # Try SMTP verification on test emails
        positive_count = 0
        negative_count = 0
        
        for test_email in test_emails:
            # These usernames should not exist, so if they're accepted, it's a catch-all
            result = self._verify_smtp(test_email, mx_records)
            
            if result.category == VALID:
                positive_count += 1
            else:
                negative_count += 1
            
            # Add delay between checks
            time.sleep(random.uniform(1, 2))
        
        # Determine if it's a catch-all
        if positive_count == len(test_emails):
            # All test emails were accepted - positive catch-all
            self.catch_all_domains.add(domain)
            return True, "positive", "All test emails were accepted"
        
        if negative_count == len(test_emails):
            # All test emails were rejected - might be negative catch-all or good validation
            # We'll need more evidence to determine if it's a negative catch-all
            
            # Try one more test with a common email pattern
            common_test_email = f"info@{domain}"
            result = self._verify_smtp(common_test_email, mx_records)
            
            if result.category == INVALID:
                # Even common email was rejected - likely negative catch-all
                self.catch_all_domains.add(domain)
                return True, "negative", "All emails including common patterns are rejected"
        
        # Not a catch-all
        self.not_catch_all_domains.add(domain)
        return False, "", "Domain properly validates email existence"
    
    def verify_custom_email(self, email: str) -> CustomEmailResult:
        """
        Verify a custom domain email using multiple methods.
        This is the main entry point for custom email verification.
        """
        # Check cache first
        if email in self.result_cache:
            return self.result_cache[email]
        
        # Step 1: Validate email format
        if not self.validate_format(email):
            result = CustomEmailResult(
                email=email,
                category=INVALID,
                reason="Invalid email format",
                verification_method="format",
                confidence=1.0
            )
            self.result_cache[email] = result
            self.save_result(result)
            return result
        
        # Step 2: Extract domain and check MX records
        _, domain = email.split('@')
        mx_records = self.get_mx_records(domain)
        
        if not mx_records:
            result = CustomEmailResult(
                email=email,
                category=INVALID,
                reason="Domain has no mail servers",
                verification_method="mx_check",
                confidence=1.0
            )
            self.result_cache[email] = result
            self.save_result(result)
            return result
        
        # Step 3: Check if it's a catch-all domain
        is_catch_all, catch_all_type, catch_all_reason = self.is_catch_all_domain(domain)
        
        if is_catch_all:
            # For positive catch-all domains, mark as risky
            if catch_all_type == "positive":
                result = CustomEmailResult(
                    email=email,
                    category=RISKY,
                    reason=f"Domain is a positive catch-all: {catch_all_reason}",
                    verification_method="catch_all_check",
                    confidence=0.5,
                    details={"catch_all_type": catch_all_type}
                )
            # For negative catch-all domains, mark as invalid
            elif catch_all_type == "negative":
                result = CustomEmailResult(
                    email=email,
                    category=INVALID,
                    reason=f"Domain is a negative catch-all: {catch_all_reason}",
                    verification_method="catch_all_check",
                    confidence=0.8,
                    details={"catch_all_type": catch_all_type}
                )
            else:
                result = CustomEmailResult(
                    email=email,
                    category=RISKY,
                    reason=f"Domain is a catch-all: {catch_all_reason}",
                    verification_method="catch_all_check",
                    confidence=0.5,
                    details={"catch_all_type": catch_all_type}
                )
            
            self.result_cache[email] = result
            self.save_result(result)
            return result
        
        # Step 4: Try to find a login page
        login_url = self.find_login_page(domain)
        
        # Step 5: Verify using the appropriate method
        if login_url:
            # Use login verification
            result = self._verify_login(email, login_url)
        else:
            # Fall back to SMTP verification
            result = self._verify_smtp(email, mx_records)
        
        # Cache and save the result
        self.result_cache[email] = result
        self.save_result(result)
        
        return result
    
    def _verify_login(self, email: str, login_url: str) -> CustomEmailResult:
        """
        Verify email using the login page.
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
                "input[name='login']"
            ]:
                try:
                    email_field = WebDriverWait(driver, 5).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, selector))
                    )
                    break
                except TimeoutException:
                    continue
            
            if not email_field:
                # If we can't find the email field, fall back to SMTP
                logger.info(f"Could not find email input field on {login_url}, falling back to SMTP")
                domain = email.split('@')[1]
                mx_records = self.get_mx_records(domain)
                return self._verify_smtp(email, mx_records)
            
            # Enter email
            email_field.clear()
            email_field.send_keys(email)
            
            # Find and click next/submit button
            next_button = None
            for selector in [
                "button[type='submit']",
                "input[type='submit']",
                "button:contains('Next')",
                "button:contains('Continue')",
                "button:contains('Sign in')",
                "button:contains('Log in')"
            ]:
                try:
                    next_button = driver.find_element(By.CSS_SELECTOR, selector)
                    break
                except NoSuchElementException:
                    continue
            
            if not next_button:
                # If we can't find the next button, fall back to SMTP
                logger.info(f"Could not find submit button on {login_url}, falling back to SMTP")
                domain = email.split('@')[1]
                mx_records = self.get_mx_records(domain)
                return self._verify_smtp(email, mx_records)
            
            # Click next button
            next_button.click()
            
            # Wait for response
            time.sleep(3)
            
            # Check for error messages
            page_source = driver.page_source.lower()
            
            # Check for phrases indicating email doesn't exist
            for phrase in [
                "no account", "doesn't exist", "not found", "invalid email",
                "no user", "user not found", "email not found", "account not found"
            ]:
                if phrase in page_source:
                    return CustomEmailResult(
                        email=email,
                        category=INVALID,
                        reason="Email address does not exist",
                        verification_method="login",
                        confidence=0.9,
                        details={"error_phrase": phrase, "login_url": login_url}
                    )
            
            # Check for password field (indicates email exists)
            try:
                WebDriverWait(driver, 5).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='password']"))
                )
                return CustomEmailResult(
                    email=email,
                    category=VALID,
                    reason="Email address exists (password prompt appeared)",
                    verification_method="login",
                    confidence=0.9,
                    details={"login_url": login_url}
                )
            except TimeoutException:
                # If we can't find a password field, check if we're still on the same page
                if urlparse(login_url).netloc in driver.current_url:
                    # We're still on the login page, but no clear error message
                    # This is risky - might exist but we can't confirm
                    return CustomEmailResult(
                        email=email,
                        category=RISKY,
                        reason="Could not determine if email exists (no password prompt or error)",
                        verification_method="login",
                        confidence=0.5,
                        details={"login_url": login_url, "current_url": driver.current_url}
                    )
                else:
                    # We were redirected somewhere else
                    return CustomEmailResult(
                        email=email,
                        category=RISKY,
                        reason="Redirected to another page",
                        verification_method="login",
                        confidence=0.6,
                        details={"login_url": login_url, "redirect_url": driver.current_url}
                    )
        
        except WebDriverException as e:
            logger.error(f"Browser error verifying {email}: {e}")
            # Fall back to SMTP
            logger.info(f"Browser error, falling back to SMTP for {email}")
            domain = email.split('@')[1]
            mx_records = self.get_mx_records(domain)
            return self._verify_smtp(email, mx_records)
        
        except Exception as e:
            logger.error(f"Error verifying {email} via login: {e}")
            # Fall back to SMTP
            logger.info(f"Login verification error, falling back to SMTP for {email}")
            domain = email.split('@')[1]
            mx_records = self.get_mx_records(domain)
            return self._verify_smtp(email, mx_records)
        
        finally:
            # Close the browser
            if driver:
                driver.quit()
    
    def _verify_smtp(self, email: str, mx_records: List[str]) -> CustomEmailResult:
        """
        Verify email using SMTP.
        """
        if not mx_records:
            return CustomEmailResult(
                email=email,
                category=INVALID,
                reason="No MX records found",
                verification_method="smtp",
                confidence=1.0
            )
        
        # Extract domain
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
                for attempt in range(2):  # Try twice
                    try:
                        with smtplib.SMTP(mx, timeout=10) as smtp:
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
                                return CustomEmailResult(
                                    email=email,
                                    category=VALID,
                                    reason="Email address exists",
                                    verification_method="smtp",
                                    confidence=0.9,
                                    details={"code": code, "mx_server": mx}
                                )
                            elif code == 550:
                                message_str = message.decode('utf-8', errors='ignore').lower()
                                
                                # Look for clear indicators that the email doesn't exist
                                if any(phrase in message_str for phrase in [
                                    "does not exist", "no such user", "user unknown",
                                    "user not found", "invalid recipient", "recipient rejected",
                                    "no mailbox", "mailbox not found"
                                ]):
                                    return CustomEmailResult(
                                        email=email,
                                        category=INVALID,
                                        reason="Email address does not exist",
                                        verification_method="smtp",
                                        confidence=0.9,
                                        details={"code": code, "message": message_str, "mx_server": mx}
                                    )
                                else:
                                    # Other 550 errors might be policy-related
                                    return CustomEmailResult(
                                        email=email,
                                        category=RISKY,
                                        reason=f"Mailbox unavailable: {message_str}",
                                        verification_method="smtp",
                                        confidence=0.7,
                                        details={"code": code, "message": message_str, "mx_server": mx}
                                    )
                            elif code in (450, 451, 452):
                                # Temporary failures, try next server
                                continue
                            else:
                                # Other responses
                                message_str = message.decode('utf-8', errors='ignore')
                                return CustomEmailResult(
                                    email=email,
                                    category=RISKY,
                                    reason=f"SMTP Error: {code} - {message_str}",
                                    verification_method="smtp",
                                    confidence=0.6,
                                    details={"code": code, "message": message_str, "mx_server": mx}
                                )
                        
                    except (socket.timeout, socket.error, smtplib.SMTPException) as e:
                        logger.debug(f"SMTP error with {mx}: {str(e)}")
                        # Continue to next attempt
                    
                    # Add delay between retries
                    if attempt < 1:  # Only delay if we're going to retry
                        time.sleep(2)
        
        # If we get here, all attempts failed
        # Fall back to pattern analysis
        return self._verify_pattern(email)
    
    def _verify_pattern(self, email: str) -> CustomEmailResult:
        """
        Verify email using pattern analysis.
        This is a last resort when other methods fail.
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
        
        # Common corporate email usernames
        if username.lower() in ["info", "contact", "support", "admin", "sales", "help", "webmaster"]:
            confidence += 0.2
        
        # Random-looking usernames are less likely to be valid
        if re.match(r'^[a-zA-Z0-9]{8,}$', username) and not any(c.isalpha() for c in username):
            confidence -= 0.1
        
        # Determine existence based on confidence
        if confidence >= 0.6:
            category = VALID
            reason = f"Likely valid based on pattern analysis (confidence: {confidence:.2f})"
        elif confidence <= 0.4:
            category = INVALID
            reason = f"Likely invalid based on pattern analysis (confidence: {confidence:.2f})"
        else:
            category = RISKY
            reason = f"Uncertain based on pattern analysis (confidence: {confidence:.2f})"
        
        return CustomEmailResult(
            email=email,
            category=category,
            reason=reason,
            verification_method="pattern",
            confidence=confidence
        )
    
    def batch_verify(self, emails: List[str]) -> Dict[str, CustomEmailResult]:
        """
        Verify multiple custom domain emails.
        """
        results = {}
        
        for email in emails:
            results[email] = self.verify_custom_email(email)
            # Add a delay between checks to avoid rate limiting
            time.sleep(random.uniform(2, 4))
        
        return results
    
    def get_results_summary(self) -> Dict[str, int]:
        """Get a summary of verification results."""
        counts = {
            VALID: 0,
            INVALID: 0,
            RISKY: 0,
            CATCH_ALL: 0
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
    verifier = CustomDomainVerifier()
    
    print("Custom Domain Email Verification Tool")
    print("====================================")
    print("1. Verify a single email")
    print("2. Verify multiple emails")
    print("3. Check if a domain is catch-all")
    print("4. Show results summary")
    print("5. Exit")
    
    choice = input("\nEnter your choice (1-5): ")
    
    if choice == "1":
        email = input("Enter an email to verify: ")
        print(f"\nVerifying {email}...")
        result = verifier.verify_custom_email(email)
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
                    result = verifier.verify_custom_email(email)
                    print(f"  Result: {result.category} - {result.reason}")
            
            except Exception as e:
                print(f"Error reading file: {e}")
        
        else:
            emails_input = input("Enter emails separated by commas: ")
            emails = [email.strip() for email in emails_input.split(",") if email.strip()]
            
            print(f"\nVerifying {len(emails)} emails...")
            for i, email in enumerate(emails, 1):
                print(f"[{i}/{len(emails)}] Verifying {email}...")
                result = verifier.verify_custom_email(email)
                print(f"  Result: {result.category} - {result.reason}")
    
    elif choice == "3":
        domain = input("Enter a domain to check: ")
        print(f"\nChecking if {domain} is a catch-all domain...")
        is_catch_all, catch_all_type, reason = verifier.is_catch_all_domain(domain)
        
        if is_catch_all:
            print(f"\nResult: {domain} IS a catch-all domain")
            print(f"Type: {catch_all_type}")
            print(f"Reason: {reason}")
            
            # Save to CSV
            verifier.save_catch_all_domain(domain, catch_all_type, reason)
        else:
            print(f"\nResult: {domain} is NOT a catch-all domain")
            print(f"Reason: {reason}")
    
    elif choice == "4":
        summary = verifier.get_results_summary()
        print("\nResults Summary:")
        print(f"Valid emails: {summary[VALID]}")
        print(f"Invalid emails: {summary[INVALID]}")
        print(f"Risky emails: {summary[RISKY]}")
        print(f"Catch-all domains: {summary[CATCH_ALL]}")
        print(f"\nTotal: {sum(summary.values())}")
        
        print("\nResults are saved in the following files:")
        for category, file_path in verifier.csv_files.items():
            print(f"{category.capitalize()}: {file_path}")
    
    else:
        print("Exiting...")