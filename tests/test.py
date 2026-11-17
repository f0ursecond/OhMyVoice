
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption
)

from main import encrypt_audio, decrypt_audio


class AudioCryptTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

        self.keys = self.root / "keys"
        self.keys.mkdir()

        self.public_path = self.keys / "public.pem"
        self.private_path = self.keys / "private.pem"

        self.input_dir = self.root / "input"
        self.input_dir.mkdir()

        self.encrypted_dir = self.root / "encrypted"
        self.encrypted_dir.mkdir()

        self.output_dir = self.root / "decrypted"
        self.output_dir.mkdir()

        self.password = "ResearchPassword2026!"

        # Generate RSA test keys
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072
        )

        public_pem = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=BestAvailableEncryption(
                self.password.encode()
            )
        )

        self.public_path.write_bytes(public_pem)
        self.private_path.write_bytes(private_pem)

        self.audio_data = (
            b"RIFF" +
            b"\x00" * 1000 +
            b"WAVE" +
            b"AudioCrypt research test data"
        )

        self.audio_path = self.input_dir / "sample.wav"
        self.audio_path.write_bytes(self.audio_data)

        self.encrypted_path = (
            self.encrypted_dir / "sample.acrypt"
        )

        self.decrypted_path = (
            self.output_dir / "sample.wav"
        )

    def tearDown(self):
        self.temp.cleanup()

    def decrypt(self, private_path=None, output=None):
        with patch("main.getpass", return_value=self.password):
            decrypt_audio(
                self.encrypted_path,
                output or self.decrypted_path,
                private_path or self.private_path
            )

    def test_audio_roundtrip(self):
        encrypt_audio(
            self.audio_path,
            self.encrypted_path,
            self.public_path
        )

        self.decrypt()

        self.assertEqual(
            self.audio_path.read_bytes(),
            self.decrypted_path.read_bytes()
        )

    def test_wrong_private_key(self):
        encrypt_audio(
            self.audio_path,
            self.encrypted_path,
            self.public_path
        )

        wrong_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072
        )

        wrong_path = self.keys / "wrong_private.pem"

        wrong_path.write_bytes(
            wrong_private.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=BestAvailableEncryption(
                    self.password.encode()
                )
            )
        )

        with self.assertRaises(Exception):
            self.decrypt(private_path=wrong_path)

    def test_tampered_ciphertext(self):
        encrypt_audio(
            self.audio_path,
            self.encrypted_path,
            self.public_path
        )

        data = bytearray(self.encrypted_path.read_bytes())
        data[-1] ^= 0x01
        self.encrypted_path.write_bytes(data)

        with self.assertRaises(Exception):
            self.decrypt()

    def test_tampered_header(self):
        encrypt_audio(
            self.audio_path,
            self.encrypted_path,
            self.public_path
        )

        data = bytearray(self.encrypted_path.read_bytes())

        # Modify one byte inside the header
        data[20] ^= 0x01

        self.encrypted_path.write_bytes(data)

        with self.assertRaises(Exception):
            self.decrypt()

    def test_mp3_format(self):
        mp3_path = self.input_dir / "sample.mp3"
        mp3_path.write_bytes(b"ID3" + b"\x00" * 500)

        encrypted = self.encrypted_dir / "sample_mp3.acrypt"
        decrypted = self.output_dir / "sample.mp3"

        encrypt_audio(
            mp3_path,
            encrypted,
            self.public_path
        )

        with patch("main.getpass", return_value=self.password):
            decrypt_audio(
                encrypted,
                decrypted,
                self.private_path
            )

        self.assertEqual(
            mp3_path.read_bytes(),
            decrypted.read_bytes()
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
