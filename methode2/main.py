import os
import csv
import time
import smtplib
import imaplib
import email
import re
import random
import logging
import uuid
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import decode_header
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Email categories
VALID = "valid"
INVALID = "invalid"
PENDING = "pending"

class EmailBounceVerifier:
    def __init__(self, 
                 smtp_server: str, 
                 smtp_port: int, 
                 imap_server: str, 
                 imap_port: int, 
                 email_address: str, 
                 password: str, 
                 output_dir: str = "./results"):
        """
        Initialize the EmailBounceVerifier with email server settings.
        
        Args:
            smtp_server: SMTP server address for sending emails
            smtp_port: SMTP server port
            imap_server: IMAP server address for checking inbox
            imap_port: IMAP server port
            email_address: Email address to use for sending/receiving
            password: Password for the email account
            output_dir: Directory to store results
        """
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.imap_server = imap_server
        self.imap_port = imap_port
        self.email_address = email_address
        self.password = password
        
        # Create output directory if it doesn't exist
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Directory for verification batches
        self.batches_dir = os.path.join(output_dir, "batches")
        os.makedirs(self.batches_dir, exist_ok=True)
        
        # Initialize CSV files
        self.csv_files = {
            VALID: os.path.join(output_dir, "valid_emails.csv"),
            INVALID: os.path.join(output_dir, "invalid_emails.csv"),
            PENDING: os.path.join(output_dir, "pending_emails.csv"),
        }
        
        # Create CSV files with headers if they don't exist
        for category, file_path in self.csv_files.items():
            if not os.path.exists(file_path):
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Email", "Batch ID", "Timestamp", "Details"])
    
    def validate_email_format(self, email_address: str) -> bool:
        """Check if the email has a valid format."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email_address))
    
    def send_verification_email(self, to_email: str, batch_id: str) -> bool:
        """
        Send a verification email to the specified address.
        
        Args:
            to_email: Email address to verify
            batch_id: Batch identifier for tracking
            
        Returns:
            bool: True if email was sent successfully, False otherwise
        """
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.email_address
            msg['To'] = to_email
            msg['Subject'] = f"Email Verification - {batch_id}"
            
            # Add a random string to avoid spam filters
            random_string = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=8))
            
            # Create email body
            body = f"""
            This is an automated email verification message.
            Verification ID: {batch_id}-{random_string}
            
            Please ignore this message.
            """
            msg.attach(MIMEText(body, 'plain'))
            
            # Connect to SMTP server
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()  # Secure the connection
                server.login(self.email_address, self.password)
                server.send_message(msg)
            
            logger.info(f"Email sent to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending email to {to_email}: {e}")
            return False
    
    def check_inbox_for_bounces(self, batch_id: str) -> Tuple[List[str], List[str]]:
        """
        Check inbox for bounce-back messages and extract invalid email addresses.
        
        Args:
            batch_id: Batch identifier to check for
            
        Returns:
            Tuple containing lists of invalid and valid email addresses
        """
        invalid_emails = []
        checked_emails = []
        
        try:
            # Connect to IMAP server
            mail = imaplib.IMAP4_SSL(self.imap_server, self.imap_port)
            mail.login(self.email_address, self.password)
            mail.select('inbox')
            
            # Search for unread messages with "Message not delivered" or similar phrases
            search_criteria = [
                '(UNSEEN SUBJECT "delivery failed")',
                '(UNSEEN SUBJECT "delivery status notification")',
                '(UNSEEN SUBJECT "undeliverable")',
                '(UNSEEN SUBJECT "returned mail")',
                '(UNSEEN SUBJECT "delivery failure")',
                '(UNSEEN SUBJECT "mail delivery failed")',
                '(UNSEEN SUBJECT "failure notice")',
                '(UNSEEN SUBJECT "message not delivered")'
            ]
            
            all_invalid_emails = []
            
            for criteria in search_criteria:
                status, messages = mail.search(None, criteria)
                
                if status != 'OK':
                    continue
                
                # Get list of message IDs
                message_ids = messages[0].split()
                
                for msg_id in message_ids:
                    # Fetch the message
                    status, msg_data = mail.fetch(msg_id, '(RFC822)')
                    
                    if status != 'OK':
                        continue
                    
                    # Parse the email
                    raw_email = msg_data[0][1]
                    msg = email.message_from_bytes(raw_email)
                    
                    # Extract subject
                    subject = self.decode_email_header(msg['Subject'])
                    
                    # Check if this is related to our batch
                    if batch_id not in subject and batch_id not in str(raw_email):
                        continue
                    
                    # Extract the body
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            content_disposition = str(part.get("Content-Disposition"))
                            
                            if "attachment" not in content_disposition and content_type in ["text/plain", "text/html"]:
                                try:
                                    body_part = part.get_payload(decode=True).decode()
                                    body += body_part
                                except:
                                    pass
                    else:
                        try:
                            body = msg.get_payload(decode=True).decode()
                        except:
                            pass
                    
                    # Extract invalid email from the body
                    invalid_email = self.extract_invalid_email_from_bounce(body, str(raw_email))
                    
                    if invalid_email:
                        all_invalid_emails.append(invalid_email)
                    
                    # Mark as read
                    mail.store(msg_id, '+FLAGS', '\\Seen')
            
            # Get list of all emails in the batch
            batch_file = os.path.join(self.batches_dir, f"{batch_id}.csv")
            if os.path.exists(batch_file):
                with open(batch_file, 'r', newline='', encoding='utf-8') as f:
                    reader = csv.reader(f)
                    next(reader)  # Skip header
                    batch_emails = [row[0] for row in reader]
                
                # Emails without bounce-backs are considered valid
                valid_emails = [email for email in batch_emails if email not in all_invalid_emails]
                
                return all_invalid_emails, valid_emails
            
            return all_invalid_emails, []
            
        except Exception as e:
            logger.error(f"Error checking inbox: {e}")
            return [], []
        finally:
            try:
                mail.close()
                mail.logout()
            except:
                pass
    
    def decode_email_header(self, header: str) -> str:
        """Decode email header to handle different encodings."""
        if not header:
            return ""
        
        decoded_parts = []
        for part, encoding in decode_header(header):
            if isinstance(part, bytes):
                if encoding:
                    try:
                        decoded_parts.append(part.decode(encoding))
                    except:
                        decoded_parts.append(part.decode('utf-8', errors='replace'))
                else:
                    decoded_parts.append(part.decode('utf-8', errors='replace'))
            else:
                decoded_parts.append(part)
        
        return ''.join(decoded_parts)
    
    def extract_invalid_email_from_bounce(self, body: str, raw_email: str) -> Optional[str]:
        """
        Extract the invalid email address from a bounce-back message.
        Prioritizes the actual error message and forwarded message section.
        
        Args:
            body: Email body text
            raw_email: Raw email content as string
        
        Returns:
            str: Invalid email address if found, None otherwise
        """
        # First priority: Look for direct error messages stating which email failed
        error_patterns = [
            r"Your message wasn't delivered to\s*<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,})>?",
            r"address wasn't found:\s*<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,})>?",
            r"Delivery to the following recipient failed permanently:\s*<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,})>?",
            r"The email account that you tried to reach does not exist.*?<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,})>?",
            r"Address not found.*?<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,})>?"
        ]
        
        for pattern in error_patterns:
            # Try in both body and raw email
            for text in [body, raw_email]:
                match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
                if match:
                    return match.group(1)
    
        # Second priority: Look for forwarded message section
        if '---------- Forwarded message ----------' in body or '---------- Forwarded message ----------' in raw_email:
            # Split at forwarded message marker
            parts = (body if '---------- Forwarded message ----------' in body else raw_email).split('---------- Forwarded message ----------')
            if len(parts) > 1:
                forwarded_part = parts[1]
                # Look for To: line in forwarded message
                to_match = re.search(r'To:\s*<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,})>?', forwarded_part, re.IGNORECASE)
                if to_match:
                    return to_match.group(1)
    
        # Last resort: Check for any other common patterns
        fallback_patterns = [
            r'Recipient:\s*<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,})>?',
            r'Unknown address:\s*<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,})>?',
            r'Invalid recipient:\s*<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,})>?'
        ]
    
        for pattern in fallback_patterns:
            for text in [body, raw_email]:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    return match.group(1)
    
        return None
    
    def save_results(self, invalid_emails: List[str], valid_emails: List[str], batch_id: str):
        """
        Save verification results to CSV files.
        
        Args:
            invalid_emails: List of invalid email addresses
            valid_emails: List of valid email addresses
            batch_id: Batch identifier
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Save invalid emails
        with open(self.csv_files[INVALID], 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            for email in invalid_emails:
                writer.writerow([email, batch_id, timestamp, "Bounce-back received"])
        
        # Save valid emails
        with open(self.csv_files[VALID], 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            for email in valid_emails:
                writer.writerow([email, batch_id, timestamp, "No bounce-back received"])
        
        # Update batch status
        batch_file = os.path.join(self.batches_dir, f"{batch_id}.csv")
        if os.path.exists(batch_file):
            # Read existing data
            emails_data = []
            with open(batch_file, 'r', newline='', encoding='utf-8') as f:
                reader = csv.reader(f)
                header = next(reader)
                for row in reader:
                    emails_data.append(row)
            
            # Update status
            with open(batch_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(header)
                for row in emails_data:
                    email = row[0]
                    if email in invalid_emails:
                        row[1] = INVALID
                    elif email in valid_emails:
                        row[1] = VALID
                    writer.writerow(row)
    
    def start_verification(self, emails: List[str]) -> str:
        """
        Start the verification process for a list of emails.
        
        Args:
            emails: List of email addresses to verify
            
        Returns:
            str: Batch ID for tracking
        """
        # Generate a batch ID
        batch_id = f"batch_{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:8]}"
        
        # Create a batch file
        batch_file = os.path.join(self.batches_dir, f"{batch_id}.csv")
        with open(batch_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Email", "Status", "Timestamp"])
            
            for email in emails:
                if self.validate_email_format(email):
                    writer.writerow([email, PENDING, datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
        
        # Send verification emails
        for email in emails:
            if self.validate_email_format(email):
                # Add to pending list
                with open(self.csv_files[PENDING], 'a', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow([email, batch_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "Verification started"])
                
                # Send email
                self.send_verification_email(email, batch_id)
                
                # Add a small delay to avoid rate limiting
                time.sleep(random.uniform(0.5, 1.5))
        
        return batch_id
    
    def get_batch_status(self, batch_id: str) -> Dict[str, int]:
        """
        Get the status of a verification batch.
        
        Args:
            batch_id: Batch identifier
            
        Returns:
            Dict with counts of emails in each status
        """
        status_counts = {
            VALID: 0,
            INVALID: 0,
            PENDING: 0
        }
        
        batch_file = os.path.join(self.batches_dir, f"{batch_id}.csv")
        if os.path.exists(batch_file):
            with open(batch_file, 'r', newline='', encoding='utf-8') as f:
                reader = csv.reader(f)
                next(reader)  # Skip header
                for row in reader:
                    if len(row) >= 2:
                        status = row[1]
                        if status in status_counts:
                            status_counts[status] += 1
                        else:
                            status_counts[PENDING] += 1
        
        return status_counts
    
    def get_all_batches(self) -> List[Dict[str, Any]]:
        """
        Get information about all verification batches.
        
        Returns:
            List of dictionaries with batch information
        """
        batches = []
        
        for filename in os.listdir(self.batches_dir):
            if filename.endswith('.csv'):
                batch_id = filename[:-4]  # Remove .csv extension
                batch_file = os.path.join(self.batches_dir, filename)
                
                # Get creation time
                created_time = datetime.fromtimestamp(os.path.getctime(batch_file)).strftime("%Y-%m-%d %H:%M:%S")
                
                # Get status counts
                status_counts = self.get_batch_status(batch_id)
                
                # Calculate total emails
                total_emails = sum(status_counts.values())
                
                # Determine batch status
                if status_counts[PENDING] == 0:
                    if total_emails == 0:
                        batch_status = "None"
                    else:
                        batch_status = "Verified"
                else:
                    batch_status = "Waiting for checking"
                
                batches.append({
                    'batch_id': batch_id,
                    'created': created_time,
                    'total_emails': total_emails,
                    'valid': status_counts[VALID],
                    'invalid': status_counts[INVALID],
                    'pending': status_counts[PENDING],
                    'status': batch_status
                })
        
        # Sort by creation time (newest first)
        batches.sort(key=lambda x: x['created'], reverse=True)
        
        return batches
    
    def process_responses(self, batch_id: str) -> Tuple[int, int]:
        """
        Process bounce-back responses for a batch.
        
        Args:
            batch_id: Batch identifier
            
        Returns:
            Tuple with counts of invalid and valid emails
        """
        # Check inbox for bounce-backs
        invalid_emails, valid_emails = self.check_inbox_for_bounces(batch_id)
        
        # Save results
        self.save_results(invalid_emails, valid_emails, batch_id)
        
        return len(invalid_emails), len(valid_emails)


def main():
    """Main function to run the email bounce verifier."""
    print("\nEmail Bounce Verifier")
    print("====================\n")
    
    # Get email credentials
    smtp_server = input("Enter SMTP server (e.g., smtp.gmail.com): ")
    smtp_port = int(input("Enter SMTP port (e.g., 587): "))
    imap_server = input("Enter IMAP server (e.g., imap.gmail.com): ")
    imap_port = int(input("Enter IMAP port (e.g., 993): "))
    email_address = input("Enter your email address: ")
    password = input("Enter your email password: ")
    
    # Initialize verifier
    verifier = EmailBounceVerifier(
        smtp_server=smtp_server,
        smtp_port=smtp_port,
        imap_server=imap_server,
        imap_port=imap_port,
        email_address=email_address,
        password=password
    )
    
    while True:
        print("\nOptions:")
        print("1. Start Verifying")
        print("2. Get Responses")
        print("3. Get Status")
        print("4. Exit")
        
        choice = input("\nEnter your choice (1-4): ")
        
        if choice == "1":
            # Start verification
            print("\nVerification Options:")
            print("1. Verify a single email")
            print("2. Verify bulk emails")
            
            verify_choice = input("\nEnter your choice (1-2): ")
            
            if verify_choice == "1":
                # Verify single email
                email = input("\nEnter the email to verify: ")
                if verifier.validate_email_format(email):
                    batch_id = verifier.start_verification([email])
                    print(f"\nVerification started with batch ID: {batch_id}")
                    print("Email sent. Please wait 1-5 minutes for responses.")
                else:
                    print("\nInvalid email format. Please try again.")
            
            elif verify_choice == "2":
                # Verify bulk emails
                print("\nBulk Verification Options:")
                print("1. Load from CSV file")
                print("2. Enter emails manually")
                
                bulk_choice = input("\nEnter your choice (1-2): ")
                
                if bulk_choice == "1":
                    # Load from CSV
                    file_path = input("\nEnter the path to the CSV file: ")
                    try:
                        emails = []
                        with open(file_path, 'r') as f:
                            for line in f:
                                email = line.strip()
                                if verifier.validate_email_format(email):
                                    emails.append(email)
                        
                        if emails:
                            batch_id = verifier.start_verification(emails)
                            print(f"\nVerification started with batch ID: {batch_id}")
                            print(f"Sent {len(emails)} emails. Please wait 1-5 minutes for responses.")
                        else:
                            print("\nNo valid emails found in the file.")
                    except Exception as e:
                        print(f"\nError reading file: {e}")
                
                elif bulk_choice == "2":
                    # Enter manually
                    emails_input = input("\nEnter emails separated by commas: ")
                    emails = [email.strip() for email in emails_input.split(",")]
                    valid_emails = [email for email in emails if verifier.validate_email_format(email)]
                    
                    if valid_emails:
                        batch_id = verifier.start_verification(valid_emails)
                        print(f"\nVerification started with batch ID: {batch_id}")
                        print(f"Sent {len(valid_emails)} emails. Please wait 1-5 minutes for responses.")
                    else:
                        print("\nNo valid emails provided.")
        
        elif choice == "2":
            # Get responses
            batches = verifier.get_all_batches()
            pending_batches = [batch for batch in batches if batch['status'] == "Waiting for checking"]
            
            if not pending_batches:
                print("\nNo batches waiting for checking.")
                continue
            
            print("\nBatches waiting for checking:")
            for i, batch in enumerate(pending_batches, 1):
                print(f"{i}. {batch['batch_id']} - Created: {batch['created']} - Pending: {batch['pending']}")
            
            batch_index = input("\nEnter the number of the batch to check (or 0 to cancel): ")
            try:
                batch_index = int(batch_index)
                if batch_index == 0:
                    continue
                
                if 1 <= batch_index <= len(pending_batches):
                    batch_id = pending_batches[batch_index - 1]['batch_id']
                    print(f"\nChecking responses for batch {batch_id}...")
                    
                    invalid_count, valid_count = verifier.process_responses(batch_id)
                    print(f"\nProcessed responses: {invalid_count} invalid, {valid_count} valid emails identified.")
                else:
                    print("\nInvalid selection.")
            except ValueError:
                print("\nInvalid input. Please enter a number.")
        
        elif choice == "3":
            # Get status
            batches = verifier.get_all_batches()
            
            if not batches:
                print("\nNo verification batches found.")
                continue
            
            print("\nVerification Batches:")
            print("-" * 100)
            print(f"{'Batch ID':<36} | {'Created':<20} | {'Status':<18} | {'Total':<6} | {'Valid':<6} | {'Invalid':<8} | {'Pending':<8}")
            print("-" * 100)
            
            for batch in batches:
                print(f"{batch['batch_id']:<36} | {batch['created']:<20} | {batch['status']:<18} | {batch['total_emails']:<6} | {batch['valid']:<6} | {batch['invalid']:<8} | {batch['pending']:<8}")
        
        elif choice == "4":
            # Exit
            print("\nExiting Email Bounce Verifier. Goodbye!")
            break
        
        else:
            print("\nInvalid choice. Please try again.")


if __name__ == "__main__":
    main()

