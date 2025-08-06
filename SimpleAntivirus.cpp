#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <unordered_set>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <windows.h>
#include <wincrypt.h>
#include <thread>
#include <mutex>
#include <codecvt>
#include <locale>

namespace fs = std::filesystem;

 
const fs::path SIGNATURE_FILE = "signatures.sdb";
const fs::path QUARANTINE_DIR = "quarantine";

 
HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

enum ConsoleColor {
    RED = 12,
    GREEN = 10,
    YELLOW = 14,
    BLUE = 9,
    WHITE = 15
};

void setColor(ConsoleColor color) {
    SetConsoleTextAttribute(hConsole, color);
}

void resetColor() {
    SetConsoleTextAttribute(hConsole, WHITE);
}

 
std::mutex mtx;

 
std::string calculate_sha256(const fs::path& file_path) {
    try {
      
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        std::wstring wide_path = converter.from_bytes(file_path.string());

       
        HANDLE hFile = CreateFileW(
            wide_path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            setColor(RED);
            std::cerr << "Dosya açılamadı: " << file_path << " (Hata: " << GetLastError() << ")" << std::endl;
            resetColor();
            return "";
        }

     
        HCRYPTPROV hProv = 0;
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            setColor(RED);
            std::cerr << "CryptAcquireContext hatası: " << GetLastError() << std::endl;
            resetColor();
            CloseHandle(hFile);
            return "";
        }

        HCRYPTHASH hHash = 0;
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            setColor(RED);
            std::cerr << "CryptCreateHash hatası: " << GetLastError() << std::endl;
            resetColor();
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            return "";
        }

      
        constexpr DWORD buffer_size = 4096;
        BYTE buffer[buffer_size];
        DWORD bytes_read = 0;

        while (ReadFile(hFile, buffer, buffer_size, &bytes_read, NULL) && bytes_read > 0) {
            if (!CryptHashData(hHash, buffer, bytes_read, 0)) {
                setColor(RED);
                std::cerr << "CryptHashData hatası: " << GetLastError() << std::endl;
                resetColor();
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                CloseHandle(hFile);
                return "";
            }
        }

      
        DWORD hash_len = 0;
        DWORD dwSize = sizeof(DWORD);
        if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&hash_len, &dwSize, 0)) {
            setColor(RED);
            std::cerr << "CryptGetHashParam hatası: " << GetLastError() << std::endl;
            resetColor();
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            return "";
        }

        std::vector<BYTE> hash_bytes(hash_len);
        if (!CryptGetHashParam(hHash, HP_HASHVAL, hash_bytes.data(), &hash_len, 0)) {
            setColor(RED);
            std::cerr << "CryptGetHashParam hatası: " << GetLastError() << std::endl;
            resetColor();
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            return "";
        }

   
        std::ostringstream os;
        os << std::hex << std::setfill('0');
        for (const auto& byte : hash_bytes) {
            os << std::setw(2) << static_cast<unsigned int>(byte);
        }

     
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);

        return os.str();
    }
    catch (const std::exception& e) {
        setColor(RED);
        std::cerr << "Hash hesaplama hatası: " << e.what() << std::endl;
        resetColor();
        return "";
    }
}
 
std::unordered_set<std::string> load_signatures() {
    std::unordered_set<std::string> signatures;
    
    if (!fs::exists(SIGNATURE_FILE)) {
        setColor(YELLOW);
        std::cerr << "İmza veritabanı bulunamadı. Yeni bir tane oluşturulacak." << std::endl;
        resetColor();
        return signatures;
    }

    std::ifstream sig_file(SIGNATURE_FILE);
    std::string line;
    
    while (std::getline(sig_file, line)) {
  
        if (!line.empty() && line.find_first_not_of(" \t") != std::string::npos && line[0] != '#') {
            
            if (line.length() == 64 && line.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos) {
              
                std::transform(line.begin(), line.end(), line.begin(), ::tolower);
                signatures.insert(line);
            }
        }
    }

    setColor(GREEN);
    std::cout << "İmza veritabanı yüklendi. " << signatures.size() << " imza bulundu." << std::endl;
    resetColor();
    return signatures;
}

 
bool quarantine_file(const fs::path& file_path) {
    try {
        if (!fs::exists(QUARANTINE_DIR)) {
            if (!fs::create_directory(QUARANTINE_DIR)) {
                setColor(RED);
                std::cerr << "Karantina klasörü oluşturulamadı!" << std::endl;
                resetColor();
                return false;
            }
        }

        auto now = std::chrono::system_clock::now();
        auto now_c = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&now_c), "%Y%m%d_%H%M%S");
        std::string timestamp = ss.str();

        fs::path new_name = QUARANTINE_DIR / (timestamp + "_" + file_path.filename().string());

  
        fs::rename(file_path, new_name);
        
        std::lock_guard<std::mutex> lock(mtx);
        setColor(YELLOW);
        std::cout << "KARANTİNA: " << file_path << " -> " << new_name << std::endl;
        resetColor();
        
        return true;
    } 
    catch (const fs::filesystem_error& e) {
        setColor(RED);
        std::cerr << "Karantina hatası: " << e.what() << std::endl;
        resetColor();
        return false;
    }
}

 
void scan_file(const fs::path& file_path, const std::unordered_set<std::string>& signatures) {
    try {
        if (!fs::is_regular_file(file_path)) return;
        
        
        uintmax_t file_size = fs::file_size(file_path);
        if (file_size > 100 * 1024 * 1024) {
            std::lock_guard<std::mutex> lock(mtx);
            setColor(BLUE);
            std::cout << "BÜYÜK DOSYA ATLANDI (" 
                      << (file_size / (1024 * 1024)) << "MB): " 
                      << file_path << std::endl;
            resetColor();
            return;
        }

    
        std::string filename = file_path.filename().string();
        if (filename == "pagefile.sys" || 
            filename == "swapfile.sys" || 
            filename == "hiberfil.sys" ||
            filename.find(".tmp") != std::string::npos) {
            return;
        }

        std::string hash = calculate_sha256(file_path);
        if (hash.empty()) return;

  
        std::transform(hash.begin(), hash.end(), hash.begin(), ::tolower);

        if (signatures.find(hash) != signatures.end()) {
            std::lock_guard<std::mutex> lock(mtx);
            setColor(RED);
            std::cout << "ZARARLI BULUNDU: " << file_path << " (Hash: " << hash << ")" << std::endl;
            resetColor();
            
            
            if (!quarantine_file(file_path)) {
                setColor(RED);
                std::cerr << "Dosya karantinaya alınamadı: " << file_path << std::endl;
                resetColor();
            }
        }
    }
    catch (const fs::filesystem_error& e) {
        std::lock_guard<std::mutex> lock(mtx);
        setColor(RED);
        std::cerr << "Dosya taranamadı: " << file_path << " - " << e.what() << std::endl;
        resetColor();
    }
}
 
void scan_directory(const fs::path& directory, const std::unordered_set<std::string>& signatures, int thread_count = 4) {
    try {
        if (!fs::exists(directory)) {
            setColor(RED);
            std::cerr << "Dizin bulunamadı: " << directory << std::endl;
            resetColor();
            return;
        }

        std::vector<fs::path> files;
        for (const auto& entry : fs::recursive_directory_iterator(directory)) {
            try {
                if (entry.is_regular_file()) {
                    files.push_back(entry.path());
                }
            }
            catch (const fs::filesystem_error& e) {
                std::lock_guard<std::mutex> lock(mtx);
                setColor(RED);
                std::cerr << "Dosya erişilemedi: " << entry.path() << " - " << e.what() << std::endl;
                resetColor();
            }
        }

        setColor(GREEN);
        std::cout << "Taranacak dosya sayısı: " << files.size() << std::endl;
        resetColor();
        setColor(YELLOW);
        std::cout << "Tarama başlıyor..." << std::endl;
        resetColor();

        auto start_time = std::chrono::high_resolution_clock::now();
        std::vector<std::thread> threads;
        size_t files_per_thread = files.size() / thread_count;

        for (int i = 0; i < thread_count; ++i) {
            size_t start = i * files_per_thread;
            size_t end = (i == thread_count - 1) ? files.size() : start + files_per_thread;

            threads.emplace_back([&, start, end] {
                for (size_t j = start; j < end; ++j) {
                    scan_file(files[j], signatures);
                }
            });
        }

        for (auto& t : threads) {
            if (t.joinable()) {
                t.join();
            }
        }

        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);

        setColor(GREEN);
        std::cout << "\nTarama tamamlandı! Süre: " << duration.count() << " saniye" << std::endl;
        resetColor();
    }
    catch (const fs::filesystem_error& e) {
        setColor(RED);
        std::cerr << "Dizin taranamadı: " << directory << " - " << e.what() << std::endl;
        resetColor();
    }
}

 
void create_eicar_test_file() {
    fs::path test_file = "eicar_test.com";
    try {
        std::ofstream out(test_file, std::ios::binary);
        if (!out) {
            throw std::runtime_error("Dosya oluşturulamadı");
        }
        
        std::string eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        out.write(eicar.c_str(), eicar.size());
        out.close();
        
        setColor(GREEN);
        std::cout << "EICAR test dosyası oluşturuldu: " << test_file << std::endl;
        resetColor();
    }
    catch (const std::exception& e) {
        setColor(RED);
        std::cerr << "Test dosyası oluşturulamadı: " << e.what() << std::endl;
        resetColor();
    }
}

 
void add_signature(const fs::path& file_path) {
    try {
        std::string hash = calculate_sha256(file_path);
        if (hash.empty()) return;

     
        std::transform(hash.begin(), hash.end(), hash.begin(), ::tolower);
 
        if (hash.length() != 64 || hash.find_first_not_of("0123456789abcdef") != std::string::npos) {
            throw std::runtime_error("Geçersiz hash formatı");
        }

        std::ofstream sig_file(SIGNATURE_FILE, std::ios::app);
        if (!sig_file) {
            throw std::runtime_error("İmza dosyası açılamadı");
        }
        
        sig_file << hash << "\n";
        sig_file.close();

        setColor(GREEN);
        std::cout << "İmza veritabanına eklendi: " << hash << std::endl;
        resetColor();
    }
    catch (const std::exception& e) {
        setColor(RED);
        std::cerr << "İmza eklenemedi: " << e.what() << std::endl;
        resetColor();
    }
}

 
void list_quarantine() {
    try {
        if (!fs::exists(QUARANTINE_DIR) || fs::is_empty(QUARANTINE_DIR)) {
            setColor(YELLOW);
            std::cout << "Karantina klasörü boş." << std::endl;
            resetColor();
            return;
        }

        setColor(BLUE);
        std::cout << "\nKarantinadaki Dosyalar:\n";
        std::cout << "------------------------\n";
        resetColor();
        
        int count = 1;
        for (const auto& entry : fs::directory_iterator(QUARANTINE_DIR)) {
            if (entry.is_regular_file()) {
                setColor(WHITE);
                std::cout << count++ << ". " << entry.path().filename() << " (";
                std::cout << (entry.file_size() / 1024) << " KB)" << std::endl;
                resetColor();
            }
        }
    }
    catch (const fs::filesystem_error& e) {
        setColor(RED);
        std::cerr << "Karantina listelenemedi: " << e.what() << std::endl;
        resetColor();
    }
}

 
void print_usage() {
    setColor(BLUE);
    std::cout << "\nWindows Basit Antivirüs - Kullanım Kılavuzu" << std::endl;
    resetColor();
    std::cout << "----------------------------------------\n";
    setColor(GREEN);
    std::cout << "  scan <dizin>        : Belirtilen dizini tarar\n";
    std::cout << "  add-signature <dosya>: Dosyayı imza veritabanına ekler\n";
    std::cout << "  create-test         : EICAR test dosyası oluşturur\n";
    std::cout << "  quarantine-list     : Karantinadaki dosyaları listeler\n";
    std::cout << "  help                : Bu yardım mesajını gösterir\n";
    resetColor();
}

void print_banner() {
    setColor(RED);
    std::cout << R"(
     ___  _  _  ___  _____  _   _  ___  ___  ___ 
    | _ )| || ||_ _||_   _|| | | || __|/ __|| _ \
    | _ \| __ | | |   | |  | |_| || _| \__ \|   /
    |___/|_||_||___|  |_|   \___/ |___||___/|_|_\
    )" << "\n\n";
    resetColor();
    setColor(BLUE);
    std::cout << "Windows için Basit Antivirüs Uygulaması\n";
    std::cout << "--------------------------------------\n\n";
    resetColor();
}

int wmain(int argc, wchar_t* argv[]) {
     
    SetConsoleOutputCP(CP_UTF8);
    
    print_banner();

    if (argc < 2) {
        print_usage();
        return 1;
    }
 
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    std::string command = converter.to_bytes(argv[1]);

    if (command == "scan" && argc >= 3) {
        std::string path = converter.to_bytes(argv[2]);
        auto signatures = load_signatures();
        scan_directory(path, signatures);
    }
    else if (command == "add-signature" && argc >= 3) {
        std::string file = converter.to_bytes(argv[2]);
        add_signature(file);
    }
    else if (command == "create-test") {
        create_eicar_test_file();
    }
    else if (command == "quarantine-list") {
        list_quarantine();
    }
    else if (command == "help") {
        print_usage();
    }
    else {
        setColor(RED);
        std::cerr << "Geçersiz komut!" << std::endl;
        resetColor();
        print_usage();
        return 1;
    }

    return 0;
}