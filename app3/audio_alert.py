import pyaudio
import wave

def play_alert():
    chunk = 1024
    file = "alert.wav"  # Ensure this file exists in the same directory

    try:
        wf = wave.open(file, 'rb')
    except FileNotFoundError:
        print(f"[!] Alert sound file not found: {file}")
        return

    p = pyaudio.PyAudio()

    stream = p.open(format=p.get_format_from_width(wf.getsampwidth()),
                    channels=wf.getnchannels(),
                    rate=wf.getframerate(),
                    output=True)

    data = wf.readframes(chunk)

    while data:
        stream.write(data)
        data = wf.readframes(chunk)

    stream.stop_stream()
    stream.close()
    p.terminate()
