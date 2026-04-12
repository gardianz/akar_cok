# Akar Cok

Repo ini berisi dua bot yang saling terhubung:

- `rootsfi/`: bot utama untuk login, cek balance, dan kirim token dari wallet RootsFi
- `walley/`: bot Walley yang menerima token masuk, melakukan accept jika pending, lalu bisa mengirim refund balik

Flow integrasi utamanya:

```text
RootsFi (R) -> Walley (W) -> RootsFi (R)
```

Contoh:

```text
R1 -> W2 -> R1
```

Artinya:

- bot RootsFi mengirim token ke wallet Walley
- jika token masuk sebagai pending di Walley, bot Walley akan mencoba `Accept`
- setelah berhasil, bot Walley menunggu jeda acak lalu mengirim balik jumlah yang sama ke wallet RootsFi asal

## Struktur Repo

```text
.
|-- rootsfi/
|   |-- index.js
|   |-- accounts.json
|   |-- config.json
|   |-- recipient.txt
|   `-- tutorial.txt
|-- walley/
|   |-- src/
|   |-- accounts.json
|   |-- config.json
|   `-- README.md
`-- .gitignore
```

## Kebutuhan

- Node.js 18+
- Google Chrome terpasang jika memakai mode browser Walley
- akses email OTP untuk akun RootsFi

## Quick Start

### 1. Install dependency

Install dependency per folder:

```bash
cd rootsfi
npm install
```

```bash
cd ../walley
npm install
```

### 2. Isi file konfigurasi

File yang biasanya perlu Anda ubah:

- `rootsfi/accounts.json`
- `rootsfi/config.json`
- `rootsfi/recipient.txt`
- `walley/accounts.json`
- `walley/config.json`

Isi di repo ini sudah disanitasi untuk publik, jadi Anda perlu menggantinya dengan akun dan konfigurasi Anda sendiri.

## Cara Menjalankan

### Menjalankan bot RootsFi

```bash
cd rootsfi
npm start
```

Saat bot berjalan, Anda akan diminta memilih mode:

- `1` = external
- `2` = internal
- `3` = balance-only

Jika ingin memakai integrasi refund Walley, pilih mode `external`.

### Menjalankan bot Walley langsung

Biasanya bot Walley dipanggil otomatis oleh RootsFi saat refund aktif. Kalau ingin mengetes Walley secara mandiri:

```bash
cd walley
npm start
```

## File Penting

### `rootsfi/accounts.json`

Berisi daftar akun RootsFi:

- `name`: nama akun
- `email`: email untuk OTP
- `address`: address RootsFi untuk internal transfer dan refund balik

### `rootsfi/recipient.txt`

Berisi daftar tujuan external. Untuk flow refund, isi file ini dengan party id Walley.

Contoh:

```text
walley-alice::1220examplepartyid000000000000000000000000000000000000000000000001
walley-bob::1220examplepartyid000000000000000000000000000000000000000000000002
```

### `rootsfi/config.json`

Konfigurasi utama RootsFi, termasuk:

- pengaturan jumlah transfer dan delay
- dashboard terminal
- Telegram log
- integrasi `walleyRefund`

### `walley/accounts.json`

Berisi akun Walley:

- `name`
- `partyHint`
- `userDataDir`
- `mnemonic`

### `walley/config.json`

Mengatur perilaku browser Walley, termasuk:

- `browserHeadless`
- auto accept pending transfer
- polling pending transfer
- delay acak setelah accept sebelum refund keluar

## Integrasi RootsFi + Walley

Agar refund otomatis berjalan:

1. isi `rootsfi/recipient.txt` dengan party id wallet Walley
2. isi `walley/accounts.json` dengan akun Walley yang akan dipakai mengirim refund
3. aktifkan `walleyRefund.enabled` di `rootsfi/config.json`
4. sesuaikan `senderMap` bila alias recipient tidak sama dengan `name` atau `partyHint` akun Walley

Contoh:

```json
"walleyRefund": {
  "enabled": true,
  "projectDir": "../walley",
  "tokenSymbol": "CC",
  "reasonPrefix": "rootsfi-refund",
  "senderMap": {
    "walley-alice": "walley-1",
    "walley-bob": "walley-2"
  }
}
```

## Dokumentasi Tambahan

- panduan RootsFi: [rootsfi/README.md](./rootsfi/README.md)
- tutorial lebih detail RootsFi: [rootsfi/tutorial.txt](./rootsfi/tutorial.txt)
- panduan Walley: [walley/README.md](./walley/README.md)

## Catatan Keamanan

Jangan commit data sensitif seperti:

- mnemonic wallet
- token Telegram
- `tokens.json`
- profile browser Walley

Repo ini sudah memakai `.gitignore` untuk menghindari file runtime lokal tersebut ikut ter-push lagi.
