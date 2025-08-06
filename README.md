Windows için Basit Antivirüs Uygulaması

Bu proje, eğitim amaçlı olarak geliştirilmiş basit bir antivirüs uygulamasıdır.

Özellikler:

- SHA-256 hash hesaplama (Windows CryptoAPI)
- Çoklu thread desteği
- Zararlı dosyaları karantinaya alma
- EICAR test dosyası oluşturma
- Renkli konsol arayüzü

Sistem Mimarisi:
    A[Kullanıcı Komutu] --> B[Dosya Tarayıcı]
    B --> C[Hash Hesaplayıcı]
    C --> D[İmza Veritabanı]
    D --> E[Karantina Sistemi]
    E --> F[Sonuç Raporu]
    G[Dosya Sistemi] --> B

Derleme Talimatları:

Visual Studio'da yeni bir Windows Konsol Uygulaması projesi oluşturun

SimpleAntivirus.cpp dosyasını projeye ekleyin

Proje özelliklerinde:

C++ Dil Standardı: ISO C++17 Standard (/std:c++17)

Karakter Seti: Unicode Karakter Seti Kullan

Projeyi derleyin (Build Solution)

Kullanım Komutları:

SimpleAntivirus.exe scan C:\Kullanıcılar\KullanıcıAdı\Belgeler
SimpleAntivirus.exe add-signature C:\yol\zararlı_dosya.exe
SimpleAntivirus.exe create-test
SimpleAntivirus.exe quarantine-list
SimpleAntivirus.exe help

Test Etme:

Test dosyası oluştur:

SimpleAntivirus.exe create-test

İmza veritabanına ekle:

SimpleAntivirus.exe add-signature eicar_test.com

Tarama yap:

SimpleAntivirus.exe scan 

Katkıda Bulunma:

Pull request'ler kabul edilir. Lütfen önce konuyla ilgili issue açın.
