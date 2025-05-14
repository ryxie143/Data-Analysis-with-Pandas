import cv2
import smtplib
import ssl
from email.message import EmailMessage
from datetime import datetime
import time
import os

# --- Email sending function ---
def send_email(image_path, to_email):
    sender_email = "valeriejaneuba.uba@cvsu.edu.ph"
    sender_pass = "appe zvdg calg uvkw"

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

# --- Main detection logic ---
def main():
    face_cascade = cv2.CascadeClassifier('haarcascade_frontalface_default.xml')
    cap = cv2.VideoCapture(0)

    if not cap.isOpened():
        print("[ERROR] Could not open video device")
        return

    # Create folder for detected images if it doesn't exist
    output_dir = "image_detected"
    os.makedirs(output_dir, exist_ok=True)

    start_time = time.time()
    sent = 0
    MAX_CAPTURES = 2
    DURATION = 10  # seconds

    while time.time() - start_time < DURATION and sent < MAX_CAPTURES:
        ret, frame = cap.read()
        if not ret:
            break

        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))

        if len(faces) > 0:
            for (x, y, w, h) in faces:
                cv2.rectangle(frame, (x, y), (x + w, y + h), (255, 0, 0), 2)

            image_filename = f"detected_face_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg"
            image_path = os.path.join(output_dir, image_filename)
            cv2.imwrite(image_path, frame)
            print(f"[+] Face detected. Sending capture #{sent + 1}...")
            send_email(image_path, "valeriejane020703@gmail.com")
            sent += 1
            time.sleep(1.5)  # Optional delay to avoid spamming

        cv2.imshow("Face Detection", frame)
        if cv2.waitKey(1) & 0xFF == ord('q'):
            print("[INFO] Quitting manually.")
            break

    print("[INFO] 10 seconds passed. Exiting...")
    cap.release()
    cv2.destroyAllWindows()

if __name__ == "__main__":
    main()
