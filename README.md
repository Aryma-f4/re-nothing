# flagr

GUI untuk mengatur target Attack/Defense, menjalankan skrip eksploit, dan mengirim flag ke API pertandingan.

## Menjalankan tiap ronde

1. Sambungkan WireGuard pada perangkat yang menjalankan flagr. Sebelum pertandingan dimulai (Round 0), box belum dapat diakses.
2. Di tab **Submit**, masukkan bearer token dari halaman Team lalu pilih **Save token**. Alternatifnya, isi username dan password lalu pilih **Login / refresh token**.
3. Di tab **Mass exploit**, isi **Own VPN IP** dan pilih **Sync teams from API**. Daftar dari `GET /api/user` akan menggantikan daftar manual; box sendiri ditandai `!` dan dilewati.
4. Masukkan satu layanan per baris, memakai port dari halaman Challenges, misalnya `web 30000`.
5. Untuk eksploit berupa skrip, masukkan satu perintah per layanan, misalnya `web = python /path/to/web_exploit.py {ip} {port}`. Skrip harus mencetak flag `GEMASTIK{...}` ke stdout atau stderr. Placeholder `{url}` menjadi `http://<ip>:<port>`; `TARGET_IP`, `TARGET_PORT`, `TARGET_URL`, `TARGET_TEAM`, dan `SERVICE` juga tersedia sebagai variabel lingkungan.
6. Untuk eksploit web berbasis request, isi **HTTP request exploit** dengan nama layanan, request sampel, dan regex flag. Klik **Save HTTP request**. Mode HTTP mengutamakan request ini dibanding perintah skrip untuk layanan yang sama.
7. Pilih **Run all now** untuk menguji konfigurasi. Saat pertandingan berjalan, set **Auto every (s)** ke `120` dan pilih **Start auto exploit**. Pengulangan dimulai saat tombol ditekan, lalu tiap 120 detik selama aplikasi terbuka. Flag dikirim ketika hasil tiap target tersedia.

Contoh request yang dapat ditempel untuk layanan `web`:

```http
GET /note?name=../../flag HTTP/1.1
Host: 10.13.37.7:21000
Accept: text/plain

```

Regex: `GEMASTIK\{[^}\s]+\}`. flagr mengganti `Host` sampel dengan IP tim dan port layanan dari konfigurasi; bagian request lain juga mendukung `{ip}` dan `{port}`. Respons dicari dengan regex tersebut. Port `21000` pada contoh hanya contoh; isi port layanan yang benar dari halaman Challenges.

Alamat target selalu berasal dari pasangan **IP tim** dan **port layanan**. Contoh: tim `10.13.37.2` dengan layanan `web 30000` berarti skrip menerima `10.13.37.2 30000`. Berpindah tim hanya mengganti IP; berpindah layanan mengganti port dan perintah yang sesuai. Port saja tidak mengambil flag: setiap layanan tetap membutuhkan skrip eksploit yang berhasil membaca flag.

Flag baru ditanam setiap 3 menit dan berlaku hingga ronde berikutnya. flagr mengirim hasil eksploit segera dalam batch (maksimal 200 flag per permintaan), menyimpan flag yang gagal terkirim untuk dicoba lagi, dan melewati flag yang sudah diproses. Interval 120 detik memberi satu pengambilan tambahan di antara pergantian ronde. Penjadwal berjalan hanya selama aplikasi terbuka.

## Dari source

```sh
python3 -m pip install -r requirements.txt
python3 flagr.py
```

Untuk membuat aplikasi mandiri: `./build.sh` di macOS/Linux atau `build.bat` di Windows.
