import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import ssl

sender_email = "valeriejaneuba.uba@cvsu.edu.ph"  # Replace with your Gmail
receiver_email = "valeriejane020703@gmail.com"  # Replace with the receiver email
sender_pass = "appe zvdg calg uvkw"  # Your app password here

msg = MIMEMultipart()
msg['From'] = sender_email
msg['To'] = receiver_email
msg['Subject'] = 'Test Email'
msg.attach(MIMEText('This is a test email.', 'plain'))

context = ssl.create_default_context()
with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as server:
    try:
        server.login(sender_email, sender_pass)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        print("[+] Test email sent successfully!")
    except Exception as e:
        print(f"[ERROR] {e}")
