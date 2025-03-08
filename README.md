
# email_verifier

Email verification using Python.

## Overview

This project provides a comprehensive email verification tool written in Python. It includes various features to validate email addresses, check their deliverability, and identify disposable or role-based accounts. The tool uses multiple techniques, including DNS checks, SMTP verification, and web scraping, to ensure accurate results.

## Features

- **Email Format Validation**: Validates the format of email addresses using regular expressions.
- **DNS Checks**: Verifies the existence of MX and A records for the domain.
- **SMTP Verification**: Checks if the email address is deliverable by communicating with the mail server.
- **Disposable Email Detection**: Identifies disposable email addresses.
- **Role Account Detection**: Detects role-based email addresses (e.g., admin@, support@).
- **Catch-All Domain Detection**: Identifies domains with catch-all configurations.
- **Domain Age Check**: Determines the age of the domain using WHOIS data.
- **Web Scraping**: Uses Selenium and BeautifulSoup to verify email addresses on login pages of known providers.

## Installation

To install the required dependencies, run the following commands:

```sh
pip install -r requirements.txt
pip install requests
pip install colorama
pip install tldextract
pip install python-whois
pip install beautifulsoup4
pip install selenium

Usage
To use the email verifier, run the v4.py script:

Enter an email to validate: example@example.com

Validation Results:
Email: example@example.com
Is Valid: ✓ (Score: 0.9)
Provider: example.com
Method: SMTP
Reason: Valid email address
This `README.md` file provides a detailed overview of the project, its features, installation instructions, usage examples, and contribution guidelines. Feel free to modify it as needed to better fit your project.
This `README.md` file provides a detailed overview of the project, its features, installation instructions, usage examples, and contribution guidelines. Feel free to modify it as needed to better fit your project.
