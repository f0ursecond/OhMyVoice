# AudioCrypt

CLI enkripsi/dekripsi audio (WAV/MP3) dengan hybrid cryptography:
AES-256-GCM untuk data audio, RSA-OAEP-SHA256 untuk membungkus key AES.

## Instalasi

1. Clone repo:

```bash
git clone <repo-url>
cd AudioCrypt
```

2. Buat virtual environment:

```bash
python -m venv venv
source venv/bin/activate
```

3. Install dependency:

```bash
pip install -r requirements.txt
```

## Penggunaan

Generate key:

```bash
python main.py keygen
```

Enkripsi audio:

```bash
python main.py encrypt --input input/rekaman.mp3 --output encrypted/rekaman.acrypt
```

Dekripsi audio:

```bash
python main.py decrypt --input encrypted/rekaman.acrypt --output decrypted/rekaman.mp3
```

Gunakan `--force` untuk menimpa file output yang sudah ada.

## Memutar file terenkripsi

Jika ingin memutar MP3 yang sudah dienkripsi, jalankan:

```bash
python play_encrypted.py
```

Catatan: script ini membaca file `encrypted/rekaman.acrypt` sebagai raw audio, bukan hasil dekripsi.

## Catatan

- File private key dan password jangan dibagikan.
- `play_encrypted.py` saat ini tidak melakukan dekripsi; jangan dipakai untuk memutar file terenkripsi.
- File besar dibaca sekaligus ke memori, jadi penggunaan untuk file sangat besar belum optimal.