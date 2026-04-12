# RootsFi Bot

Folder ini berisi bot utama untuk:

- login ke RootsFi
- cek balance
- kirim token internal atau external
- menampilkan dashboard log
- mengirim status ke Telegram
- memicu refund otomatis lewat bot Walley

## File yang Perlu Diisi

- `accounts.json`: daftar akun RootsFi
- `config.json`: pengaturan utama bot
- `recipient.txt`: daftar tujuan external

## Jalankan

```bash
npm install
npm start
```

## Mode Bot

- `external`: kirim ke alamat di `recipient.txt`
- `internal`: kirim antar akun di `accounts.json`
- `balance-only`: hanya cek balance

Kalau ingin flow refund Walley, gunakan mode `external`.

## Integrasi Refund Walley

Jika `walleyRefund.enabled` aktif di `config.json`, maka setelah transfer external sukses:

```text
RootsFi -> Walley -> RootsFi
```

Bot akan:

1. kirim token dari RootsFi ke wallet Walley
2. menjalankan proyek Walley
3. mencoba accept transfer masuk jika masih pending
4. menunggu jeda acak
5. mengirim balik jumlah yang sama ke address RootsFi asal

## Baca Juga

- tutorial pemula: [tutorial.txt](./tutorial.txt)
- panduan repo utama: [../README.md](../README.md)
