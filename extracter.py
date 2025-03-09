import csv
import re

# Define the path to the CSV file
csv_file_path = 'C:/project/SMTP-CRACKER-V2/largelist.csv'

# Define a regular expression pattern to match email addresses
email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

# Initialize a set to store unique email addresses
emails = set()

# Read the CSV file and extract email addresses
with open(csv_file_path, 'r', encoding='utf-8') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        for cell in row:
            matches = email_pattern.findall(cell)
            for match in matches:
                emails.add(match)

# Write the extracted email addresses to a new file
output_file_path = 'C:/project/SMTP-CRACKER-V2/extracted_emails.txt'
with open(output_file_path, 'w', encoding='utf-8') as outfile:
    for email in sorted(emails):
        outfile.write(email + '\n')

print(f'Extracted {len(emails)} unique email addresses.')
print(f'Email addresses have been saved to {output_file_path}.')