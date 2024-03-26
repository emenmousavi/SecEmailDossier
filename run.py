import dns.resolver
import smtplib
import re
import logging

def extract_domain(email_address):
    return email_address.split('@')[-1]

def check_mx_records(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_servers = [str(mx.exchange) for mx in mx_records]
        logging.info("MX records found. Email server(s): %s", mx_servers)
        return mx_servers
    except dns.resolver.NoAnswer:
        logging.error("No MX records found for the domain. Email address might be invalid.")
        return []

def validate_email_syntax(email_address):
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email_address):
        logging.error("Invalid email address syntax: %s", email_address)
        return False
    return True

def connect_and_verify_email(mx_servers, email_address):
    for mx_server in mx_servers:
        try:
            with smtplib.SMTP(mx_server) as server:
                server.set_debuglevel(0)
                server.starttls()
                server.ehlo()
                code, _ = server.verify(email_address)
                if code == 250:
                    logging.info("Email address %s exists on server %s.", email_address, mx_server)
                    return
                else:
                    logging.info("Email address %s does not exist on server %s.", email_address, mx_server)
        except smtplib.SMTPConnectError:
            logging.error("Failed to connect to server %s.", mx_server)
        except smtplib.SMTPException as e:
            logging.error("Error verifying email on server %s: %s", mx_server, e)

    logging.info("Email address %s does not exist on any of the servers.", email_address)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    email_address = input("Enter the email address to verify: ")
    domain = extract_domain(email_address)
    mx_servers = check_mx_records(domain)
    
    if mx_servers and validate_email_syntax(email_address):
        connect_and_verify_email(mx_servers, email_address)
