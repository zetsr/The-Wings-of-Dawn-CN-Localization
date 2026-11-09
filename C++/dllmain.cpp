#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <format>

#include "SDKTools/SDKTools.h"
#include "CppSDK/SDK.hpp"
#include "Minhook/include/MinHook.h" 

bool InitConsole()
{
    if (!AllocConsole()) {
        return false;
    }

    FILE* dummy;
    freopen_s(&dummy, "CONOUT$", "w", stdout);
    freopen_s(&dummy, "CONIN$", "r", stdin);

    SetConsoleTitleA("Debug Window");
    std::cout << "[+] Console Initialized Successfully.\n";
    return true;
}

void ScanAllFonts()
{
    SDK::TUObjectArray* ObjectArray = SDK::UObject::GObjects.operator->();
    if (!ObjectArray) return;

    int32_t TotalObjects = ObjectArray->Num();
    for (int32_t i = 0; i < TotalObjects; ++i)
    {
        SDK::UObject* Obj = ObjectArray->GetByIndex(i);
        if (!Obj) continue;

        if (Obj->IsA(SDK::UFont::StaticClass()))
        {
            std::cout << Obj->GetFullName() << "\n";
        }
    }
}

void PostRender(SDK::UGameViewportClient* GameViewportClient, SDK::UCanvas* Canvas) {
    SDKTools::PostRender(reinterpret_cast<void*>(GameViewportClient), reinterpret_cast<void*>(Canvas));

    static float DeltaTime = 0.016f;
    static float time = 0.f;
    time += DeltaTime;

    if (time >= 2.f) {
        time = 0.f;
        ScanAllFonts();
    }

    SDK::UFont* font = reinterpret_cast<SDK::UFont*>(SDKTools::GetFontByName("Font Roboto.Roboto"));

    if (font && font->IsA(SDK::UFont::StaticClass())) {
        static bool bHasExported = false;
        if (!bHasExported) {
            bHasExported = true;
            SDKTools::ExportFont(font);
        }

        // 屏幕渲染调试
        std::string str_ptr = std::format("{}", reinterpret_cast<uintptr_t>(font));
        std::wstring wstr_ptr = std::filesystem::path(str_ptr).wstring();

        Canvas->K2_DrawText(font, L"Test! 测试！1", { 5.f, 5.f }, { 1.f, 1.f }, { 1.f, 1.f, 1.f, 1.f }, 1.f, { 1.f, 1.f, 1.f, 1.f }, { 1.f, 1.f }, false, false, false, { 1.f, 1.f, 1.f, 1.f });
        Canvas->K2_DrawText(font, SDK::FString(wstr_ptr.c_str()), { 5.f, 55.f }, { 1.f, 1.f }, { 1.f, 1.f, 1.f, 1.f }, 1.f, { 1.f, 1.f, 1.f, 1.f }, { 1.f, 1.f }, false, false, false, { 1.f, 1.f, 1.f, 1.f });
    }
}

// 主线程
DWORD WINAPI MainThread(LPVOID lpParam)
{
    HMODULE hModule = static_cast<HMODULE>(lpParam);

    if (!InitConsole()) {
        ExitThread(0);
        return 0;
    }

    while (!SDK::UWorld::GetWorld());

    SDKTools::Init();

    // 挂钩 PostRender
    SDKTools::AddHook("PostRender", -1, "40 55 53 56 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? 48 8B F2 48 8B D9 E8");

    return 0;
}

// DLL 入口点
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, MainThread, hModule, 0, nullptr);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}