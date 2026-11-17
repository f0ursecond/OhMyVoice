# Laporan Proyek: AudioCrypt

## 1. Identitas

- Nama: Alif Zulfanur
- NIM: A11.2024.15582
- Mata kuliah: Kriptografi

## 2. Abstrak

AudioCrypt adalah program baris perintah untuk mengenkripsi dan mendekripsi file audio WAV atau MP3. Program memakai AES-256-GCM untuk isi file dan RSA-OAEP-SHA256 untuk membungkus kunci AES. Hasil enkripsi disimpan dalam format container buatan sendiri dengan ekstensi `.acrypt`. Pengujian menunjukkan roundtrip data berhasil, kunci salah ditolak, dan perubahan data terdeteksi.

## 3. Pendahuluan

### 3.1 Latar belakang

File audio sering disimpan atau dikirim tanpa perlindungan. Jika file jatuh ke pihak lain, isinya dapat dibaca langsung. AudioCrypt dibuat untuk melindungi isi file audio dengan enkripsi, sekaligus memastikan integritas data.

### 3.2 Rumusan masalah

1. Bagaimana melindungi file audio WAV/MP3 dengan enkripsi yang kuat?
2. Bagaimana memastikan file tidak diubah setelah dienkripsi?
3. Bagaimana menyimpan metadata dan ciphertext dalam satu format yang dapat dibaca kembali?

### 3.3 Tujuan

1. Membuat program enkripsi dan dekripsi audio berbasis CLI.
2. Menggunakan kombinasi AES dan RSA.
3. Memverifikasi integritas file saat dekripsi.
4. Menyediakan pengujian otomatis untuk skenario dasar.

### 3.4 Batasan

1. Hanya mendukung WAV dan MP3.
2. Seluruh file dibaca ke memori, belum cocok untuk file sangat besar.
3. Program memerlukan password untuk private key.
4. `play_encrypted.py` tidak melakukan dekripsi.

## 4. Landasan teori

### 4.1 AES-256-GCM

AES-256-GCM adalah cipher simetris dengan mode GCM. Mode ini memberikan kerahasiaan dan autentikasi data. Nonce harus unik untuk setiap enkripsi dengan kunci yang sama.

### 4.2 RSA-OAEP

RSA-OAEP digunakan untuk membungkus kunci AES. Kunci publik dipakai saat enkripsi. Kunci privat dipakai saat dekripsi. Padding OAEP dengan SHA-256 dipakai untuk keamanan.

### 4.3 Hybrid encryption

Enkripsi hibrida memakai AES untuk data besar dan RSA untuk kunci AES. Cara ini lebih efisien daripada mengenkripsi seluruh file dengan RSA.

### 4.4 AAD

AAD adalah data tambahan yang ikut diautentikasi tetapi tidak dienkripsi. Dalam AudioCrypt, AAD berisi magic, panjang header, dan header JSON.

## 5. Perancangan sistem

### 5.1 Alur enkripsi

1. Baca file audio.
2. Buat kunci AES 256-bit dan nonce 12 byte.
3. Bungkus kunci AES dengan RSA public key.
4. Buat metadata JSON.
5. Hitung AAD.
6. Enkripsi audio dengan AES-GCM.
7. Tulis container: magic + panjang header + header + ciphertext.

### 5.2 Alur dekripsi

1. Baca file `.acrypt`.
2. Parse dan validasi container.
3. Buka private key dengan password.
4. Unwrap kunci AES.
5. Dekripsi dan verifikasi ciphertext.
6. Cek ukuran dan ekstensi file hasil.
7. Tulis file output.

### 5.3 Format container

| Bagian | Ukuran | Keterangan |
|---|---|---|
| Magic | 8 byte | `ACRYPT1\n` |
| Panjang header | 4 byte | big-endian unsigned int |
| Header | variabel | JSON metadata |
| Ciphertext | variabel | AES-GCM output |

### 5.4 Metadata

Metadata berisi:

- version
- algorithm
- key_algorithm
- original_filename
- original_size
- nonce
- encrypted_key

## 6. Implementasi

Program utama ada di `main.py`. Fungsi utama:

- `generate_keys`: membuat keypair RSA 3072-bit.
- `encrypt_audio`: enkripsi file audio.
- `decrypt_audio`: dekripsi file `.acrypt`.
- `parse_container`: parse dan validasi container.
- `atomic_write`: penulisan file secara atomik.

CLI menyediakan tiga perintah:

```bash
python main.py keygen
python main.py encrypt --input input/rekaman.mp3 --output encrypted/rekaman.acrypt
python main.py decrypt --input encrypted/rekaman.acrypt --output decrypted/rekaman.mp3
```

## 7. Pengujian

Pengujian dilakukan dengan `unittest` pada `tests/test.py`.

| Skenario | Hasil |
|---|---|
| Roundtrip WAV | PASS |
| Kunci privat salah | PASS |
| Ciphertext diubah | PASS |
| Header diubah | PASS |
| Roundtrip MP3 | PASS |

Hasil akhir: 5 test, semua PASS.

Contoh ukuran dari pengujian MP3:

- Input: 503 byte
- Output terenkripsi: 1215 byte

## 8. Analisis keamanan

1. AES-GCM memberikan autentikasi data. Perubahan ciphertext atau header akan gagal saat dekripsi.
2. RSA-OAEP-SHA256 dipakai untuk membungkus kunci AES.
3. Private key disimpan dengan enkripsi password dan permission 0600.
4. AAD mencegah perubahan metadata tanpa terdeteksi.
5. Risiko: private key dan file contoh tersimpan di repo. Sebaiknya jangan commit key dan artifact.
6. Risiko: password lemah tetap diterima jika panjang minimal 12.

## 9. Hasil

Program dapat mengenkripsi dan mendekripsi audio dengan integritas terverifikasi. Pengujian otomatis menunjukkan semua skenario dasar berhasil.

## 10. Kesimpulan dan saran

### Kesimpulan

AudioCrypt berhasil mengimplementasikan enkripsi hibrida untuk file audio. Format container dan validasi integritas bekerja. Pengujian menunjukkan roundtrip dan deteksi tampering berhasil.

### Saran

1. Tambahkan streaming untuk file besar.
2. Perbaiki atau hapus `play_encrypted.py`.
3. Tambahkan README dan `.gitignore`.
4. Jangan commit private key dan artifact.

## 11. Daftar pustaka

1. Python `cryptography` documentation.
2. NIST, Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM).
3. RFC 8017, PKCS #1: RSA Cryptography Specifications Version 2.2.

## 12. Lampiran

- `main.py`
- `tests/test.py`
- `requirements.txt`
- Output pengujian: 5 test PASS