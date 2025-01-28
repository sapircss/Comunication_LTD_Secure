import smtplib

def test_smtp(smtp_server, smtp_port, email_address, email_password):
    """
    Tests SMTP connection for a given email configuration.

    Args:
        smtp_server (str): The SMTP server address.
        smtp_port (int): The SMTP server port.
        email_address (str): The email address used for login.
        email_password (str): The app-specific password for the email.

    Returns:
        None
    """
    try:
        print(f"Testing SMTP connection for {email_address}...")
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Start TLS encryption
            server.login(email_address, email_password)
            print(f"SMTP login successful for {email_address}!")
    except smtplib.SMTPAuthenticationError as e:
        print(f"SMTP Authentication error for {email_address}: {e}")
    except Exception as e:
        print(f"SMTP connection failed for {email_address}: {e}")


# Test Gmail Configuration
gmail_config = {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "email_address": "sapirshenhav@gmail.com",  # Replace with your Gmail address
    "email_password": "afwa nkoj lqms rhis"  # Replace with your Gmail app-specific password
}

# Test Hotmail Configuration
hotmail_config = {
    "smtp_server": "smtp.live.com",
    "smtp_port": 587,
    "email_address": "sapirshenhav@hotmail.com",  # Replace with your Hotmail address
    "email_password": "your-hotmail-app-password"  # Replace with your Hotmail app-specific password
}

# Run tests
test_smtp(
    gmail_config["smtp_server"],
    gmail_config["smtp_port"],
    gmail_config["email_address"],
    gmail_config["email_password"],
)

test_smtp(
    hotmail_config["smtp_server"],
    hotmail_config["smtp_port"],
    hotmail_config["email_address"],
    hotmail_config["email_password"],
)
