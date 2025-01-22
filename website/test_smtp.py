import smtplib

smtp_server = "smtp.gmail.com"
smtp_port = 587
email_address = "sapirshenhav@gmail.com"  # Replace with your email
email_password = "afwa nkoj lqms rhis"  # Replace with your app password

try:
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()  # Start TLS encryption
        server.login(email_address, email_password)
        print("SMTP login successful!")
except smtplib.SMTPAuthenticationError as e:
    print(f"SMTP Authentication error: {e}")
except Exception as e:
    print(f"SMTP connection failed: {e}")
