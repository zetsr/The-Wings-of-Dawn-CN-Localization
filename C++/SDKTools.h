#pragma once

#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <filesystem>
#include <format>
#include <cstdint>
#include <algorithm>
#include <string_view>

// 引入 MinHook 头文件
#include "../Minhook/include/MinHook.h"

// 前置声明外部 dllmain.cpp 中定义的类型与函数
namespace SDK {
    class UGameViewportClient;
    class UCanvas;
    class UObject;
    class UFont;
}

// 声明外部由 dllmain.cpp 实现的 PostRender 劫持函数
void PostRender(SDK::UGameViewportClient* GameViewportClient, SDK::UCanvas* Canvas);

namespace SDKTools {

    // 保存原版 PostRender 函数地址的跳板函数指针
    typedef void(__fastcall* tPostRender)(void* this_ptr, void* canvas);
    inline tPostRender oPostRender = nullptr;

    // 内部跳板：当引擎命中 Hook 时，跳转到外部编写的 PostRender
    inline void __fastcall HookedPostRender(void* GameViewportClient, void* Canvas) {
        ::PostRender(reinterpret_cast<SDK::UGameViewportClient*>(GameViewportClient),
            reinterpret_cast<SDK::UCanvas*>(Canvas));
    }

    // 1. 初始化 MinHook 环境
    inline bool Init() {
        if (MH_Initialize() != MH_OK) {
            std::cout << "[-] MinHook Initialization Failed (or already initialized).\n";
            return false;
        }
        std::cout << "[+] SDKTools & MinHook Initialized Successfully.\n";
        return true;
    }

    // 2. 特征码内存扫描器（支持 IDA 格式通配符 "40 55 ? ? 48"）
    inline uintptr_t FindPattern(const char* signature) {
        MODULEINFO modInfo = { 0 };
        HMODULE hModule = GetModuleHandleA(nullptr);
        if (!hModule) return 0;
        GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO));

        uintptr_t startAddress = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
        uintptr_t endAddress = startAddress + modInfo.SizeOfImage;

        std::vector<int> patternBytes;
        std::stringstream ss(signature);
        std::string byteStr;

        while (ss >> byteStr) {
            if (byteStr == "?" || byteStr == "??") {
                patternBytes.push_back(-1);
            }
            else {
                patternBytes.push_back(std::stoi(byteStr, nullptr, 16));
            }
        }

        const size_t patternLength = patternBytes.size();
        for (uintptr_t i = startAddress; i < endAddress - patternLength; ++i) {
            bool found = true;
            for (size_t j = 0; j < patternLength; ++j) {
                if (patternBytes[j] != -1 && patternBytes[j] != *reinterpret_cast<unsigned char*>(i + j)) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return i;
            }
        }
        return 0;
    }

    // 3. 原函数转发：外部 PostRender 第一行调用的 SDKTools::PostRender
    inline void PostRender(void* GameViewportClient, void* Canvas) {
        if (oPostRender) {
            oPostRender(GameViewportClient, Canvas);
        }
    }

    // 4. Hook 注册器（适配 dllmain.cpp 的 AddHook 调用）
    inline bool AddHook(const char* name, int vtableIndex, const char* sig) {
        std::string hookName(name);

        if (hookName == "PostRender") {
            std::cout << "[*] Scanning pattern for " << hookName << "...\n";
            uintptr_t targetAddress = FindPattern(sig);

            if (!targetAddress) {
                std::cout << "[-] Failed to find signature for " << hookName << "!\n";
                return false;
            }

            std::cout << "[+] Found " << hookName << " at address: 0x"
                << std::hex << std::uppercase << targetAddress << std::dec << "\n";

            if (MH_CreateHook(reinterpret_cast<LPVOID>(targetAddress),
                reinterpret_cast<LPVOID>(&HookedPostRender),
                reinterpret_cast<LPVOID*>(&oPostRender)) != MH_OK) {
                std::cout << "[-] MH_CreateHook failed for " << hookName << "!\n";
                return false;
            }

            if (MH_EnableHook(reinterpret_cast<LPVOID>(targetAddress)) != MH_OK) {
                std::cout << "[-] MH_EnableHook failed for " << hookName << "!\n";
                return false;
            }

            std::cout << "[+] Successfully hooked " << hookName << "!\n";
            return true;
        }

        std::cout << "[-] Unknown hook target: " << hookName << "\n";
        return false;
    }

    // 5. 资产检索器：在全局 UObject 池中按名称匹配字体
    template<typename T = void>
    inline void* GetFontByName(const std::string& fontName) {
        auto ObjectArray = SDK::UObject::GObjects.operator->();
        if (!ObjectArray) return nullptr;

        int32_t count = ObjectArray->Num();
        for (int32_t i = 0; i < count; ++i) {
            auto Obj = ObjectArray->GetByIndex(i);
            if (!Obj) continue;

            if (Obj->IsA(SDK::UFont::StaticClass())) {
                std::string fullName = Obj->GetFullName();
                std::string name = Obj->GetName();

                if (fullName == fontName || name == fontName || fullName.find(fontName) != std::string::npos) {
                    return reinterpret_cast<void*>(Obj);
                }
            }
        }
        return nullptr;
    }

    // ====================== 字体导出内部辅助模块 ======================
    namespace Internal {
        inline bool IsValidFontHeader(const uint8_t* data) {
            if (!data) return false;
            bool is_ttf = (data[0] == 0x00 && data[1] == 0x01 && data[2] == 0x00 && data[3] == 0x00);
            bool is_otf = (data[0] == 'O' && data[1] == 'T' && data[2] == 'T' && data[3] == 'O');
            bool is_true = (data[0] == 't' && data[1] == 'r' && data[2] == 'u' && data[3] == 'e');

            if (!is_ttf && !is_otf && !is_true) return false;

            uint16_t numTables = static_cast<uint16_t>((data[4] << 8) | data[5]);
            return (numTables >= 4 && numTables <= 80);
        }

        inline size_t CalculateFontBinarySize(const uint8_t* data, size_t max_scan_size) {
            if (!IsValidFontHeader(data)) return 0;

            uint16_t numTables = static_cast<uint16_t>((data[4] << 8) | data[5]);
            size_t total_size = 12 + numTables * 16;
            if (total_size > max_scan_size) return 0;

            for (int i = 0; i < numTables; ++i) {
                size_t record_offset = 12 + i * 16;
                if (record_offset + 16 > max_scan_size) return 0;

                uint32_t offset = (static_cast<uint32_t>(data[record_offset + 8]) << 24) |
                    (static_cast<uint32_t>(data[record_offset + 9]) << 16) |
                    (static_cast<uint32_t>(data[record_offset + 10]) << 8) |
                    (static_cast<uint32_t>(data[record_offset + 11]));

                uint32_t length = (static_cast<uint32_t>(data[record_offset + 12]) << 24) |
                    (static_cast<uint32_t>(data[record_offset + 13]) << 16) |
                    (static_cast<uint32_t>(data[record_offset + 14]) << 8) |
                    (static_cast<uint32_t>(data[record_offset + 15]));

                size_t table_end = offset + length;
                if (table_end > total_size) {
                    total_size = table_end;
                }
            }

            if (total_size > 10 * 1024 && total_size <= max_scan_size) {
                return total_size;
            }
            return 0;
        }

        inline bool BufferContainsString(const uint8_t* buffer, size_t size, std::string_view target) {
            if (size < target.size()) return false;
            const uint8_t* end = buffer + size - target.size();
            for (const uint8_t* p = buffer; p <= end; ++p) {
                if (memcmp(p, target.data(), target.size()) == 0) {
                    return true;
                }
            }
            return false;
        }
    }

    // 6. 【核心接口】字体导出引擎：传入 UFont* 即可导出所有矢量字体与元数据
    template<typename FontType = SDK::UFont>
    inline bool ExportFont(FontType* font, const std::filesystem::path& target_dir = "C:/FontExport") {
        if (!font) return false;

        namespace fs = std::filesystem;
        fs::path export_dir = target_dir;
        std::error_code ec;
        fs::create_directories(export_dir, ec);
        if (ec) {
            export_dir = fs::current_path() / "ExportedFonts";
            fs::create_directories(export_dir, ec);
        }

        std::cout << std::format("[*] Target Export Directory: {}\n", export_dir.string());

        // 导出元数据
        fs::path info_file_path = export_dir / "font_info.txt";
        std::ofstream info_file(info_file_path);
        if (info_file.is_open()) {
            info_file << std::format("Font FullName: {}\n", font->GetFullName());
            info_file << std::format("EmScale: {}\n", font->EmScale);
            info_file << std::format("Ascent: {}\n", font->Ascent);
            info_file << std::format("Descent: {}\n", font->Descent);
            info_file << std::format("Leading: {}\n\n", font->Leading);

            auto& default_fonts = font->CompositeFont.DefaultTypeface.Fonts;
            for (int i = 0; i < default_fonts.Num(); ++i) {
                auto& entry = default_fonts[i];
                info_file << std::format("[{}] Entry Name: {}\n", i, entry.Name.ToString());
                if (entry.Font.FontFaceAsset) {
                    info_file << std::format("    Asset: {}\n", entry.Font.FontFaceAsset->GetFullName());
                    info_file << std::format("    Asset Class: {}\n", entry.Font.FontFaceAsset->Class->GetName());
                }
            }
            info_file.close();
            std::cout << std::format("[+] Metadata saved to: {}\n", info_file_path.string());
        }

        // 自动提取匹配关键字（如 "Roboto"）
        std::string font_keyword = font->GetName();
        std::cout << std::format("[*] Scanning process memory for '{}' vector fonts...\n", font_keyword);

        SYSTEM_INFO sys_info;
        GetSystemInfo(&sys_info);

        uint8_t* current_addr = reinterpret_cast<uint8_t*>(sys_info.lpMinimumApplicationAddress);
        uint8_t* max_addr = reinterpret_cast<uint8_t*>(sys_info.lpMaximumApplicationAddress);

        int exported_font_count = 0;
        std::vector<uintptr_t> dumped_addresses;

        MEMORY_BASIC_INFORMATION mbi;
        while (current_addr < max_addr && VirtualQuery(current_addr, &mbi, sizeof(mbi))) {
            DWORD mask = PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE;
            if ((mbi.State == MEM_COMMIT) && (mbi.Protect & mask) && !(mbi.Protect & PAGE_GUARD)) {
                const uint8_t* page_start = reinterpret_cast<const uint8_t*>(mbi.BaseAddress);
                size_t page_size = mbi.RegionSize;

                for (size_t offset = 0; offset + 12 < page_size; offset += 4) {
                    const uint8_t* candidate = page_start + offset;

                    __try {
                        if (Internal::IsValidFontHeader(candidate)) {
                            uintptr_t cand_addr = reinterpret_cast<uintptr_t>(candidate);
                            bool already_dumped = false;
                            for (auto addr : dumped_addresses) {
                                if (std::abs(static_cast<long long>(cand_addr - addr)) < 1024 * 1024) {
                                    already_dumped = true;
                                    break;
                                }
                            }
                            if (already_dumped) continue;

                            size_t max_allowed = page_size - offset;
                            size_t font_size = Internal::CalculateFontBinarySize(candidate, max_allowed);

                            if (font_size > 0 && Internal::BufferContainsString(candidate, font_size, font_keyword)) {
                                std::string ext = (candidate[0] == 'O') ? ".otf" : ".ttf";

                                std::string sub_name = "Font";
                                if (Internal::BufferContainsString(candidate, font_size, "BoldItalic")) sub_name = "BoldItalic";
                                else if (Internal::BufferContainsString(candidate, font_size, "Bold")) sub_name = "Bold";
                                else if (Internal::BufferContainsString(candidate, font_size, "Italic")) sub_name = "Italic";
                                else if (Internal::BufferContainsString(candidate, font_size, "Light")) sub_name = "Light";
                                else if (Internal::BufferContainsString(candidate, font_size, "Regular")) sub_name = "Regular";

                                fs::path out_path = export_dir / std::format("{}_{}_{}{}", font_keyword, sub_name, exported_font_count, ext);
                                std::ofstream out_file(out_path, std::ios::binary);
                                if (out_file.is_open()) {
                                    out_file.write(reinterpret_cast<const char*>(candidate), font_size);
                                    out_file.close();

                                    std::cout << std::format("[+] SUCCESS! Extracted: {} (Size: {:.2f} KB) at 0x{:X}\n",
                                        out_path.filename().string(), font_size / 1024.0, cand_addr);
                                    dumped_addresses.push_back(cand_addr);
                                    exported_font_count++;
                                }
                            }
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {}
                }
            }
            current_addr += mbi.RegionSize;
        }

        std::cout << std::format("[OK] Export Completed! Total {} vector fonts exported to {}\n",
            exported_font_count, export_dir.string());
        return exported_font_count > 0;
    }
}