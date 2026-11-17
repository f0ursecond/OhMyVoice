
import numpy as np
import sounddevice as sd


def play_acrypt(file_path, sample_rate=44100):
    """
    Listening njirr.
    """

    with open(file_path, "rb") as file:
        encrypted_data = file.read()

    if not encrypted_data:
        raise ValueError("Kosong")

    
    audio_data = np.frombuffer(encrypted_data, dtype=np.uint8)

    
    audio_data = (audio_data.astype(np.float32) - 127.5) / 127.5

    
    sd.play(audio_data, samplerate=sample_rate)
    sd.wait()

play_acrypt("encrypted/rekaman.acrypt")
