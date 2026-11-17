
import argparse
import base64
import json
import os
import struct
import sys
from pathlib import Path
from getpass import getpass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM



MAGIC = b"ACRYPT1\n"
VERSION = 1

AES_KEY_SIZE = 32       
AES_NONCE_SIZE = 12     
RSA_KEY_SIZE = 3072

SUPPORTED_FORMATS = {".wav", ".mp3"}

MAX_HEADER_SIZE = 1024 * 1024


def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64_decode(data: str) -> bytes:
    return base64.b64decode(data, validate=True)


def check_audio_format(path: Path):
    if path.suffix.lower() not in SUPPORTED_FORMATS:
        raise ValueError(
            "Format audio tidak didukung. Gunakan WAV atau MP3."
        )


def check_output(path: Path, force: bool):
    if path.exists() and not force:
        raise FileExistsError(
            f"File {path} sudah ada. Gunakan --force untuk menimpa."
        )


def atomic_write(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)

    temp_path = path.with_name(path.name + ".tmp")

    try:
        with open(temp_path, "xb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())

        os.replace(temp_path, path)

    finally:
        if temp_path.exists():
            temp_path.unlink()

def generate_keys(
    public_path: Path,
    private_path: Path,
    force: bool = False
):
    check_output(public_path, force)
    check_output(private_path, force)

    password = getpass("Buat password private key: ")
    confirmation = getpass("Ulangi password: ")

    if password != confirmation:
        raise ValueError("Password tidak cocok.")

    if len(password) < 12:
        raise ValueError(
            "Gunakan password minimal 12 karakter."
        )

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE
    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode("utf-8")
        )
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    atomic_write(private_path, private_pem)
    try:
        os.chmod(private_path, 0o600)
        atomic_write(public_path, public_pem)
    except Exception:
        private_path.unlink(missing_ok=True)
        raise

    print("\n[+] RSA key berhasil dibuat.")
    print(f"[+] Public key : {public_path}")
    print(f"[+] Private key: {private_path}")
    print("[!] Simpan private key dan password dengan aman.")


def load_public_key(path: Path):
    with open(path, "rb") as file:
        key = serialization.load_pem_public_key(file.read())

    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("Public key bukan RSA.")

    if key.key_size < 3072:
        raise ValueError("RSA key minimal 3072 bit.")

    return key

def load_private_key(path: Path):
    password = getpass("Masukkan password private key: ")

    with open(path, "rb") as file:
        key = serialization.load_pem_private_key(
            file.read(),
            password=password.encode("utf-8")
        )

    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("Private key bukan RSA.")

    if key.key_size < 3072:
        raise ValueError("RSA key minimal 3072 bit.")

    return key

def encrypt_audio(
    input_path: Path,
    output_path: Path,
    public_key_path: Path,
    force: bool = False
):
    check_audio_format(input_path)
    check_output(output_path, force)

    if not input_path.is_file():
        raise FileNotFoundError(input_path)

    public_key = load_public_key(public_key_path)

    
    audio_data = input_path.read_bytes()

    
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(AES_NONCE_SIZE)

    
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    metadata = {
        "version": VERSION,
        "algorithm": "AES-256-GCM",
        "key_algorithm": "RSA-OAEP-SHA256",
        "original_filename": input_path.name,
        "original_size": len(audio_data),
        "nonce": b64_encode(nonce),
        "encrypted_key": b64_encode(encrypted_key)
    }

    header = json.dumps(
        metadata,
        separators=(",", ":")
    ).encode("utf-8")

    header_length = struct.pack(">I", len(header))

    
    aad = MAGIC + header_length + header

    
    ciphertext = AESGCM(aes_key).encrypt(
        nonce,
        audio_data,
        aad
    )

    
    encrypted_container = (
        MAGIC +
        header_length +
        header +
        ciphertext
    )

    atomic_write(output_path, encrypted_container)

    print("\n[+] AUDIO ENCRYPTION SUCCESSFUL")
    print(f"[+] Input       : {input_path}")
    print(f"[+] Output      : {output_path}")
    print(f"[+] Original    : {len(audio_data)} bytes")
    print(f"[+] Encrypted   : {len(encrypted_container)} bytes")
    print("[+] Algorithm   : AES-256-GCM")
    print("[+] Key wrapping: RSA-OAEP-SHA256")


def parse_container(data: bytes):
    minimum_size = len(MAGIC) + 4

    if len(data) < minimum_size:
        raise ValueError("File terenkripsi terlalu kecil.")

    if data[:len(MAGIC)] != MAGIC:
        raise ValueError("Format file AudioCrypt tidak valid.")

    position = len(MAGIC)

    header_length = struct.unpack(
        ">I",
        data[position:position + 4]
    )[0]

    position += 4

    if header_length == 0 or header_length > MAX_HEADER_SIZE:
        raise ValueError("Ukuran metadata tidak valid.")

    if len(data) < position + header_length + 16:
        raise ValueError("File terenkripsi tidak lengkap.")

    header = data[position:position + header_length]
    ciphertext = data[position + header_length:]

    try:
        metadata = json.loads(header.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Metadata terenkripsi tidak valid.") from error

    if not isinstance(metadata, dict):
        raise ValueError("Struktur metadata tidak valid.")

    if metadata.get("version") != VERSION:
        raise ValueError("Versi AudioCrypt tidak didukung.")

    if metadata.get("algorithm") != "AES-256-GCM":
        raise ValueError("Algoritma tidak dikenali.")

    if metadata.get("key_algorithm") != "RSA-OAEP-SHA256":
        raise ValueError("Algoritma pembungkus kunci tidak dikenali.")

    aad = MAGIC + struct.pack(">I", header_length) + header

    return metadata, ciphertext, aad


def decrypt_audio(
    input_path: Path,
    output_path: Path,
    private_key_path: Path,
    force: bool = False
):
    check_output(output_path, force)

    if not input_path.is_file():
        raise FileNotFoundError(input_path)

    private_key = load_private_key(private_key_path)

    encrypted_data = input_path.read_bytes()

    metadata, ciphertext, aad = parse_container(encrypted_data)

    
    encrypted_key = b64_decode(metadata["encrypted_key"])

    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    if len(aes_key) != AES_KEY_SIZE:
        raise ValueError("Panjang AES key tidak valid.")

    nonce = b64_decode(metadata["nonce"])

    if len(nonce) != AES_NONCE_SIZE:
        raise ValueError("Panjang nonce tidak valid.")

    
    try:
        audio_data = AESGCM(aes_key).decrypt(
            nonce,
            ciphertext,
            aad
        )
    except Exception as error:
        raise ValueError(
            "Autentikasi gagal. File mungkin telah dimodifikasi "
            "atau kunci yang digunakan tidak sesuai."
        ) from error

    
    expected_size = metadata.get("original_size")

    if not isinstance(expected_size, int) or expected_size < 0:
        raise ValueError("Metadata ukuran audio tidak valid.")

    if len(audio_data) != expected_size:
        raise ValueError("Ukuran audio hasil dekripsi tidak cocok.")

    
    original_name = metadata.get("original_filename")

    if not isinstance(original_name, str):
        raise ValueError("Nama file asli tidak valid.")

    original_extension = Path(original_name).suffix.lower()

    if original_extension not in SUPPORTED_FORMATS:
        raise ValueError("Ekstensi audio dalam metadata tidak valid.")

    if output_path.suffix.lower() != original_extension:
        raise ValueError(
            f"Ekstensi output harus {original_extension}."
        )

    atomic_write(output_path, audio_data)

    print("\n[+] AUDIO DECRYPTION SUCCESSFUL")
    print(f"[+] Input      : {input_path}")
    print(f"[+] Output     : {output_path}")
    print(f"[+] Restored   : {len(audio_data)} bytes")
    print("[+] Integrity  : VERIFIED")
    print("[+] Format     : PRESERVED")


def main():
    parser = argparse.ArgumentParser(
        description="AudioCrypt - Hybrid Audio Encryption System"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True
    )

    
    keygen_parser = subparsers.add_parser(
        "keygen",
        help="Generate RSA public/private key"
    )

    keygen_parser.add_argument(
        "--public",
        type=Path,
        default=Path("keys/public_key.pem")
    )

    keygen_parser.add_argument(
        "--private",
        type=Path,
        default=Path("keys/private_key.pem")
    )

    keygen_parser.add_argument(
        "--force",
        action="store_true"
    )

    
    encrypt_parser = subparsers.add_parser(
        "encrypt",
        help="Encrypt WAV or MP3 audio"
    )

    encrypt_parser.add_argument("--input", type=Path, required=True)
    encrypt_parser.add_argument("--output", type=Path, required=True)

    encrypt_parser.add_argument(
        "--public",
        type=Path,
        default=Path("keys/public_key.pem")
    )

    encrypt_parser.add_argument(
        "--force",
        action="store_true"
    )

    
    decrypt_parser = subparsers.add_parser(
        "decrypt",
        help="Decrypt AudioCrypt file"
    )

    decrypt_parser.add_argument("--input", type=Path, required=True)
    decrypt_parser.add_argument("--output", type=Path, required=True)

    decrypt_parser.add_argument(
        "--private",
        type=Path,
        default=Path("keys/private_key.pem")
    )

    decrypt_parser.add_argument(
        "--force",
        action="store_true"
    )

    args = parser.parse_args()

    try:
        if args.command == "keygen":
            generate_keys(
                args.public,
                args.private,
                args.force
            )

        elif args.command == "encrypt":
            encrypt_audio(
                args.input,
                args.output,
                args.public,
                args.force
            )

        elif args.command == "decrypt":
            decrypt_audio(
                args.input,
                args.output,
                args.private,
                args.force
            )

    except KeyboardInterrupt:
        print("\n[!] Proses dibatalkan.")
        sys.exit(130)

    except Exception as error:
        print(f"\n[ERROR] {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
