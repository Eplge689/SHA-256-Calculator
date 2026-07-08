#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <cstdint>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

std::wstring ReadConsoleInput() {
    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    WCHAR buffer[1024];
    DWORD charsRead = 0;

    std::wcout << L"[Input]: ";
    std::wcout.flush();

    if (!ReadConsoleW(hInput, buffer, 1023, &charsRead, NULL)) {
        return L"";
    }

    std::wstring result(buffer, charsRead);
    while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n')) {
        result.pop_back();
    }
    return result;
}

std::string WStringToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

std::string WStringToGbk(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size_needed = WideCharToMultiByte(936, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(936, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

std::string ComputeSha256(const std::string& input) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    DWORD hashLen = 32;
    std::vector<uint8_t> hash(hashLen);
    std::ostringstream oss;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return "Error: Open Algorithm";

    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "Error: Create Hash";
    }

    status = BCryptHashData(hHash, (PUCHAR)input.data(), (ULONG)input.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "Error: Hash Data";
    }

    status = BCryptFinishHash(hHash, hash.data(), hashLen, 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) return "Error: Finish Hash";

    for (uint8_t byte : hash) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return oss.str();
}

int main() {
    SetConsoleOutputCP(CP_UTF8);

    std::wcout << L"========================================\n";
    std::wcout << L"      SHA-256 Calculator\n";
    std::wcout << L"========================================\n";
    std::wcout << L"[Disclaimer\n";
    std::wcout << L"1.This tool is strictly for educational,\n";
    std::wcout << L"  technical research, and legal data\n";
    std::wcout << L"  integrity verification purposes only.\n";
    std::wcout << L"2.Strictly prohibited for any illegal \n";
    std::wcout << L"  cracking or infringement activities.\n";
    std::wcout << L"3.The software is provided 'AS IS'. The\n";
    std::wcout << L"  author assumes NO liability for any\n";
    std::wcout << L"  damages or legal issues arising from use.\n";
    std::wcout << L"========================================\n";
    std::wcout << L"Type your text below (or 'q' to exit):\n";
    std::wcout << L">>> ";
    std::wcout.flush();


    while (true) {
        std::wstring input = ReadConsoleInput();

        if (input.empty()) continue;
        if (input == L"q" || input == L"quit" || input == L"exit") break;

        std::string utf8_data = WStringToUtf8(input);
        std::string gbk_data = WStringToGbk(input);

        std::cout << "[UTF-8 Hash]: " << ComputeSha256(utf8_data) << "\n";
        std::cout << "[ GBK  Hash]: " << ComputeSha256(gbk_data) << "\n";
        std::cout << "--------------------------------------------------\n";
    }

    return 0;
}