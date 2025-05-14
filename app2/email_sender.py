import cv2
import smtplib
import ssl
from email.message import EmailMessage
from datetime import datetime
import time

# Function to send an email with the image attachment
def send_email(image_path, to_email):
    sender_email = "valeriejaneuba.uba@cvsu.edu.ph"
    sender_pass = "appe zvdg calg uvkw"  # App password

    msg = EmailMessage()
    msg['Subject'] = '🔔 Person Detected!'
    msg['From'] = sender_email
    msg['To'] = to_email
    msg.set_content('Motion detected. See attached image.')

    with open(image_path, 'rb') as img:
        msg.add_attachment(img.read(), maintype='image', subtype='jpeg', filename='intruder.jpg')

    context = ssl.create_default_context()
    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls(context=context)
        server.login(sender_email, sender_pass)
        server.send_message(msg)
        print("[+] Email sent.")

# Load the Haar Cascade classifier
face_cascade = cv2.CascadeClassifier('haarcascade_frontalface_default.xml')  # Ensure this file is in your directory

# Start video capture
cap = cv2.VideoCapture(0)

# Check if the webcam is opened correctly
if not cap.isOpened():
    print("[ERROR] Could not open video device")
    exit()

# Track time and captures
start_time = time.time()
capture_count = 0
max_captures = 2
duration_seconds = 10

while True:
    if time.time() - start_time > duration_seconds:
        print("[INFO] 10 seconds passed. Exiting...")
        break

    ret, frame = cap.read()
    if not ret:
        break

    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))

    if len(faces) > 0 and capture_count < max_captures:
        for (x, y, w, h) in faces:
            cv2.rectangle(frame, (x, y), (x + w, y + h), (255, 0, 0), 2)

        image_path = f"detected_face_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg"
        cv2.imwrite(image_path, frame)
        print(f"[+] Face detected. Sending capture #{capture_count + 1}...")
        send_email(image_path, "valeriejane020703@gmail.com")
        capture_count += 1
        time.sleep(1)  # Optional: delay to avoid rapid multiple detections

    cv2.imshow('Face Detection', frame)

    if cv2.waitKey(1) & 0xFF == ord('q'):
        print("[INFO] Quitting manually.")
        break

# Clean up
cap.release()
cv2.destroyAllWindows()
