# Walley Transfer Bot

Bot CLI untuk transfer antar wallet Walley dengan flow yang mengikuti frontend `walley.cc` yang terverifikasi dari browser:

- mode utama memakai `browser-session` dengan profile browser per akun
- bootstrap akun baru memakai flow `/recover` yang benar-benar ada di UI Walley
- validasi akun tetap memakai `GET /v1/party?party_id=...`
- transfer live mengikuti urutan UI Walley:
  - buka `Send Transfer`
  - isi receiver, token, amount, reason
  - klik `Send`
  - verifikasi `Sign Transaction`
  - klik `Confirm`
- incoming transfer pending bisa di-`Accept` otomatis lebih dulu sebelum bot mengirim refund keluar

## Mode yang tersedia

### `browser-session` (direkomendasikan)

- Satu akun = satu `userDataDir`
- Setelah bootstrap berhasil, sesi dan signing key tetap tinggal di profile browser
- Ini paling cocok dengan temuan live Walley, karena signing key browser tersimpan sebagai `CryptoKey` non-extractable di IndexedDB
- Bot menggunakan browser yang sama untuk langkah signing final

### `api-mnemonic` (fallback eksperimen)

- Mode awal berbasis mnemonic tetap disimpan sebagai fallback
- Jangan dijadikan jalur utama dulu sampai derivasi mnemonic Node tervalidasi penuh terhadap akun Walley live

## File input

- `config.json`
- `accounts.json`
- `transfers.json`

Template awal ada di:

- `config.example.json`
- `accounts.example.json`
- `transfers.example.json`

## Menjalankan

```bash
npm install
```

```bash
node src/index.js
```

## Contoh konfigurasi browser-session

`config.json`

```json
{
  "sessionMode": "browser-session",
  "transferMode": "manual",
  "browserChannel": "chrome",
  "browserHeadless": true,
  "autoAcceptPendingTransfers": true,
  "pendingTransferPollIntervalMs": 4000,
  "pendingTransferPollAttempts": 6,
  "postAcceptTransferDelayMinMs": 3000,
  "postAcceptTransferDelayMaxMs": 8000,
  "bootstrapMissingSession": true
}
```

`accounts.json`

```json
[
  {
    "name": "walley-1",
    "partyHint": "walley-alice",
    "userDataDir": "./profiles/walley-1",
    "mnemonic": "word1 word2 ... word24"
  }
]
```

## Catatan penting

- `partyHint` harus diisi persis seperti yang dipakai Walley, misalnya `walley-alice`.
- Bot ini baru mengimplementasikan mode transfer `manual`.
- Pada verifikasi live tanggal 7 April 2026, transfer `2 CC` dari `walley-gosjavar` ke `ilhamgod::...4126d4` berhasil melalui flow UI yang sama seperti di atas.
- Pada verifikasi live tanggal 11 April 2026, incoming transfer pending di dashboard Walley terbukti memakai tombol `Accept`, yang memanggil `POST /v1/transfers/accept/prepare` dengan body `{ contract_id, party_id }`, lalu dilanjutkan ke dialog `Confirm Transaction`.
- Request live yang terverifikasi saat transfer:
  - `POST /v1/transfers/prepare`
  - `POST /v1/transfers/accept/prepare`
  - `POST /v1/transactions/submit-and-wait`
- Jika penerima belum mengaktifkan `Transfer Preapproval`, transfer bisa masuk status pending dan butuh acceptance terpisah.
- Dengan `autoAcceptPendingTransfers: true`, bot browser-session sekarang akan mencoba menerima pending incoming transfer lebih dulu sebelum transfer keluar dijalankan.
- Setelah pending transfer berhasil di-accept, bot akan menunggu jeda acak dari `postAcceptTransferDelayMinMs` sampai `postAcceptTransferDelayMaxMs` sebelum refund keluar dikirim.
- Di mode `browser-session`, bot baru aman untuk transfer yang receiver preapproval-nya sudah aktif. Otomasi enable preapproval via UI belum saya tandai final karena jalur disabled-to-enabled belum diverifikasi langsung.
- Passkey/WebAuthn belum diotomasi sebagai login primer. Bot mengandalkan profile browser yang sudah login atau bootstrap `/recover`.
