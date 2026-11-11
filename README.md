# flagr

GUI untuk mengatur target Attack/Defense, menjalankan skrip eksploit, dan mengirim flag ke API pertandingan.

## Menjalankan tiap ronde

1. Sambungkan WireGuard pada perangkat yang menjalankan flagr. Sebelum pertandingan dimulai (Round 0), box belum dapat diakses.
2. Di tab **Submit**, masukkan bearer token dari halaman Team lalu pilih **Save token**. Alternatifnya, isi username dan password lalu pilih **Login / refresh token**.
3. Di tab **Mass exploit**, isi **Own VPN IP** dan pilih **Sync teams from API**. Daftar dari `GET /api/user` akan menggantikan daftar manual; box sendiri ditandai `!` dan dilewati.
4. Masukkan satu layanan per baris, memakai port dari halaman Challenges, misalnya `web 30000`.
5. Masukkan satu perintah eksploit per layanan, misalnya `web = python3 /path/to/web_exploit.py {ip} {port}`. Skrip harus mencetak flag `GEMASTIK{...}` ke stdout atau stderr. Placeholder `{url}` menjadi `http://<ip>:<port>`; `TARGET_IP`, `TARGET_PORT`, `TARGET_URL`, `TARGET_TEAM`, dan `SERVICE` juga tersedia sebagai variabel lingkungan.
6. Pilih **Run all now** untuk menguji konfigurasi. Saat pertandingan berjalan, set **Auto every (s)** ke `180` dan pilih **Start auto exploit**. Pengulangan dimulai saat tombol ditekan, lalu tiap 180 detik tanpa menunggu selesainya seluruh target untuk mengirim flag yang sudah diperoleh.

Alamat target selalu berasal dari pasangan **IP tim** dan **port layanan**. Contoh: tim `10.13.37.2` dengan layanan `web 30000` berarti skrip menerima `10.13.37.2 30000`. Berpindah tim hanya mengganti IP; berpindah layanan mengganti port dan perintah yang sesuai. Port saja tidak mengambil flag: setiap layanan tetap membutuhkan skrip eksploit yang berhasil membaca flag.

Flag baru ditanam setiap 3 menit dan berlaku hingga ronde berikutnya. flagr mengirim hasil eksploit segera dalam batch (maksimal 200 flag per permintaan), menyimpan flag yang gagal terkirim untuk dicoba lagi, dan melewati flag yang sudah diproses. Interval 180 detik mengikuti durasi ronde, tetapi tidak otomatis tersinkron dengan Tick 0; mulai otomatisasi saat ronde baru dimulai untuk mendekati batas ronde.

## Dari source

```sh
python3 -m pip install -r requirements.txt
python3 flagr.py
```

Untuk membuat aplikasi mandiri: `./build.sh` di macOS/Linux atau `build.bat` di Windows.
