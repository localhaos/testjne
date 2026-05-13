#include <jni.h>
#include <string>
#include <vector>
#include <map>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <android/log.h>
#include <pthread.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <link.h>
#include <sys/syscall.h>
#include <errno.h>
#include <mutex>
#include <memory>
#include <sstream>
#include <iomanip>
#include <algorithm>

// --- And64InlineHook (własna implementacja) ---
#include "And64InlineHook.h"

// --- KONFIGURACJA ---
#define LOG_TAG "StealthLoader"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Makra dla stron pamięci
#define PAGE_SIZE sysconf(_SC_PAGESIZE)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define PAGE_START(addr) ((uintptr_t)(addr) & PAGE_MASK)

// Klucz XOR (może być losowo generowany przy kompilacji)
constexpr uint8_t XOR_KEY = 0x55;

// --- STRUKTURY DANYCH ---
struct BytePattern {
    std::vector<uint8_t> pattern;
    std::vector<bool> mask; // true = sprawdzaj bajt, false = wildcard
    size_t offset;         // Offset od początku wzorca
};

struct HookConfig {
    std::string library_name;
    std::string function_name;
    void* new_func;
    void** orig_func;
    BytePattern pattern;   // Opcjonalny wzorec do wyszukiwania adresu
    size_t patch_offset;   // Offset od wzorca
};

struct PatchConfig {
    std::string library_name;
    BytePattern pattern;
    std::vector<uint8_t> new_bytes;
    size_t patch_offset;
};

struct BypassConfig {
    std::string library_name;
    std::string function_name;
    void* new_func;
    void** orig_func;
    BytePattern pattern;
    size_t patch_offset;
};

// --- ZMIENNE GLOBALNE ---
static JavaVM* g_jvm = nullptr;
static pthread_t g_patch_thread;
static volatile bool g_stop_thread = false;
static std::mutex g_memory_mutex;
static std::map<std::string, uintptr_t> g_library_bases;
static std::vector<HookConfig> g_hooks;
static std::vector<PatchConfig> g_patches;
static std::vector<BypassConfig> g_bypasses;
static std::vector<InlineHook*> g_inline_hooks;
static std::vector<std::string> g_blacklist = {
    decrypt_string({0x1A, 0x10, 0x08, 0x01, 0x04, 0x00}), // "frida"
    decrypt_string({0x1B, 0x10, 0x07, 0x04, 0x00, 0x1E, 0x07}), // "gadget"
    decrypt_string({0x1C, 0x11, 0x0E, 0x0D, 0x2F, 0x06, 0x21}), // "gum-js"
    decrypt_string({0x28, 0x21, 0x26, 0x20, 0x1E, 0x21, 0x28}), // "agent.so"
    decrypt_string({0x2B, 0x20, 0x27, 0x20, 0x26, 0x21, 0x28, 0x2D}), // "linjector"
    decrypt_string({0x2D, 0x20, 0x27, 0x21, 0x28, 0x26})  // "magisk"
};

// --- FUNKCJE POMOCNICZE ---
std::string decrypt_string(const std::vector<uint8_t>& cipher) {
    std::string output;
    for (size_t i = 0; i < cipher.size(); ++i) {
        output += static_cast<char>(cipher[i] ^ XOR_KEY);
    }
    return output;
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    std::istringstream iss(hex);
    std::string byte_str;
    while (iss >> byte_str) {
        bytes.push_back(static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16)));
    }
    return bytes;
}

// --- WYSZUKIWANIE WZORCÓW BAJTÓW ---
uintptr_t find_pattern(uintptr_t start, uintptr_t end, const BytePattern& pattern) {
    if (pattern.pattern.empty() || start >= end) return 0;

    const uint8_t* mem = reinterpret_cast<const uint8_t*>(start);
    size_t mem_size = end - start;
    size_t pattern_size = pattern.pattern.size();

    for (size_t i = 0; i <= mem_size - pattern_size; ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern_size; ++j) {
            if (pattern.mask[j] && mem[i + j] != pattern.pattern[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            return start + i + pattern.offset;
        }
    }
    return 0;
}

uintptr_t find_pattern_in_library(const std::string& lib_name, const BytePattern& pattern) {
    uintptr_t lib_base = find_library_base(lib_name.c_str());
    if (!lib_base) return 0;

    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[1024];
    uintptr_t lib_end = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, lib_name.c_str())) {
            uintptr_t start, end;
            if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                lib_end = end;
                break;
            }
        }
    }
    fclose(fp);

    if (!lib_end) return 0;
    return find_pattern(lib_base, lib_end, pattern);
}

uintptr_t find_library_base(const char* lib_name) {
    auto it = g_library_bases.find(lib_name);
    if (it != g_library_bases.end()) {
        return it->second;
    }

    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[1024];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, lib_name)) {
            base = static_cast<uintptr_t>(strtoull(line, nullptr, 16));
            break;
        }
    }
    fclose(fp);

    if (base) {
        g_library_bases[lib_name] = base;
    }
    return base;
}

bool is_library_loaded(const std::string& lib_name) {
    return find_library_base(lib_name.c_str()) != 0;
}

// --- PATCHOWANIE PAMIĘCI ---
bool change_memory_protection(void* addr, int prot) {
    uintptr_t page_start = PAGE_START(reinterpret_cast<uintptr_t>(addr));
    if (mprotect(reinterpret_cast<void*>(page_start), PAGE_SIZE, prot) != 0) {
        LOGE("mprotect failed at %p (prot=%d): %s", addr, prot, strerror(errno));
        return false;
    }
    return true;
}

bool hex_patch(uintptr_t addr, const std::vector<uint8_t>& new_bytes) {
    std::lock_guard<std::mutex> lock(g_memory_mutex);

    if (!change_memory_protection(reinterpret_cast<void*>(addr), PROT_READ | PROT_WRITE | PROT_EXEC)) {
        return false;
    }

    memcpy(reinterpret_cast<void*>(addr), new_bytes.data(), new_bytes.size());

    if (!change_memory_protection(reinterpret_cast<void*>(addr), PROT_READ | PROT_EXEC)) {
        return false;
    }

    #if defined(__arm__) || defined(__aarch64__)
        __builtin___clear_cache(reinterpret_cast<char*>(addr), reinterpret_cast<char*>(addr + new_bytes.size()));
    #endif

    return true;
}

void wipe_elf_header(void* base_addr) {
    if (!base_addr) return;
    uintptr_t page_start = PAGE_START(reinterpret_cast<uintptr_t>(base_addr));
    if (!change_memory_protection(reinterpret_cast<void*>(page_start), PROT_READ | PROT_WRITE)) {
        return;
    }
    memset(base_addr, 0, 64);
    change_memory_protection(reinterpret_cast<void*>(page_start), PROT_READ | PROT_EXEC);
}

// --- INLINE HOOKI (And64InlineHook) ---
InlineHook* hook_function(uintptr_t target_addr, void* new_func, void** orig_func) {
    InlineHook* hook = new InlineHook;
    if (InlineHook_init(hook, target_addr, reinterpret_cast<uintptr_t>(new_func)) != 0) {
        LOGE("Failed to init hook for %p", (void*)target_addr);
        delete hook;
        return nullptr;
    }

    if (InlineHook_enable(hook) != 0) {
        LOGE("Failed to enable hook for %p", (void*)target_addr);
        delete hook;
        return nullptr;
    }

    if (orig_func) {
        *orig_func = reinterpret_cast<void*>(hook->targetAddr);
    }

    g_inline_hooks.push_back(hook);
    LOGI("[+] Hooked %p -> %p", (void*)target_addr, new_func);
    return hook;
}

void unhook_function(InlineHook* hook) {
    if (!hook) return;
    InlineHook_disable(hook);
    auto it = std::find(g_inline_hooks.begin(), g_inline_hooks.end(), hook);
    if (it != g_inline_hooks.end()) {
        g_inline_hooks.erase(it);
    }
    delete hook;
}

// --- HOOKI SYSTEMOWE (STEALTH) ---
bool contains_blacklist(const char* str) {
    if (!str) return false;
    for (const auto& keyword : g_blacklist) {
        if (strstr(str, keyword.c_str())) {
            return true;
        }
    }
    return false;
}

static int (*orig_openat)(int, const char*, int, mode_t) = nullptr;
int my_openat(int dirfd, const char* pathname, int flags, mode_t mode) {
    if (contains_blacklist(pathname)) {
        errno = ENOENT;
        return -1;
    }
    return orig_openat(dirfd, pathname, flags, mode);
}

static char* (*orig_fgets)(char*, int, FILE*) = nullptr;
char* my_fgets(char* s, int size, FILE* stream) {
    char* result = orig_fgets(s, size, stream);
    if (result && contains_blacklist(result)) {
        return my_fgets(s, size, stream);
    }
    return result;
}

// --- PRZYKŁADOWE BYPASY ---
int (*old_IsEnable)(int, char*, int) = nullptr;
int IsEnable(int a1, char* NameOfThread, int a3) {
    if (strstr(NameOfThread, "opcode_scan") || strstr(NameOfThread, "memory_scan")) {
        LOGI("[!] Blocked scan: %s", NameOfThread);
        return 0;
    }
    return old_IsEnable(a1, NameOfThread, a3);
}

void (*orig_AnoSDKExport)() = nullptr;
void hook_AnoSDKExport() {
    void* buf = malloc(0x31);
    if (buf) {
        memset(buf, 0, 0x31);
        free(buf);
    }
    orig_AnoSDKExport();
}

// --- ŁADOWANIE BEZPLIKOWE (MEMFD) ---
void* load_from_assets_stealth(JNIEnv* env, jobject assetMgr) {
    AAssetManager* mgr = AAssetManager_fromJava(env, assetMgr);
    if (!mgr) {
        LOGE("Failed to get AssetManager");
        return nullptr;
    }

    AAssetDir* dir = AAssetManager_openDir(mgr, "");
    if (!dir) {
        LOGE("Failed to open asset directory");
        return nullptr;
    }

    const char* fileName;
    while ((fileName = AAssetManager_getNextFileName(dir)) != nullptr) {
        AAsset* asset = AAssetManager_open(mgr, fileName, AASSET_MODE_BUFFER);
        if (!asset) continue;

        size_t size = AAsset_getLength(asset);
        std::vector<unsigned char> buffer(size);
        if (AAsset_read(asset, buffer.data(), size) <= 0) {
            AAsset_close(asset);
            continue;
        }

        if (size >= 4 && buffer[0] == 0x7F && buffer[1] == 'E' && buffer[2] == 'L' && buffer[3] == 'F') {
            LOGI("[*] Found ELF in assets: %s", fileName);

            int fd = syscall(__NR_memfd_create, "system_lib", MFD_CLOEXEC);
            if (fd == -1) {
                LOGE("memfd_create failed: %s", strerror(errno));
                AAsset_close(asset);
                continue;
            }

            if (ftruncate(fd, size) == -1 || write(fd, buffer.data(), size) != static_cast<ssize_t>(size)) {
                LOGE("Failed to write to memfd");
                close(fd);
                AAsset_close(asset);
                continue;
            }

            char path[64];
            snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
            void* handle = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
            if (!handle) {
                LOGE("dlopen failed: %s", dlerror());
                close(fd);
                AAsset_close(asset);
                continue;
            }

            struct link_map* map;
            if (dlinfo(handle, RTLD_DI_LINKMAP, &map) == 0) {
                wipe_elf_header(reinterpret_cast<void*>(map->l_addr));
                LOGI("[+] Library loaded at %p (memfd)", reinterpret_cast<void*>(map->l_addr));
            }
            close(fd);
            AAssetManager_closeDir(dir);
            return handle;
        }
        AAsset_close(asset);
    }
    AAssetManager_closeDir(dir);
    return nullptr;
}

// --- WĄTEK PATCHOWANIA ---
void* game_patch_thread(void*) {
    LOGI("[*] Waiting for target libraries...");

    // Czekaj na załadowanie bibliotek
    for (const auto& patch : g_patches) {
        while (!g_stop_thread && !is_library_loaded(patch.library_name)) {
            usleep(100000);
        }
        if (g_stop_thread) return nullptr;
    }

    // Zastosuj patch'e
    for (const auto& patch : g_patches) {
        uintptr_t target_addr = find_pattern_in_library(patch.library_name, patch.pattern);
        if (!target_addr) {
            LOGE("Pattern not found in %s", patch.library_name.c_str());
            continue;
        }
        target_addr += patch.patch_offset;
        if (!hex_patch(target_addr, patch.new_bytes)) {
            LOGE("Failed to patch %s at %p", patch.library_name.c_str(), (void*)target_addr);
        } else {
            LOGI("[+] Patched %s at %p", patch.library_name.c_str(), (void*)target_addr);
        }
    }

    // Zastosuj hooki i bypassy
    for (const auto& hook : g_hooks) {
        uintptr_t target_addr = 0;
        if (!hook.pattern.pattern.empty()) {
            target_addr = find_pattern_in_library(hook.library_name, hook.pattern);
            if (!target_addr) {
                LOGE("Pattern not found for %s in %s", hook.function_name.c_str(), hook.library_name.c_str());
                continue;
            }
            target_addr += hook.patch_offset;
        } else {
            void* addr = dlsym(dlopen(hook.library_name.c_str(), RTLD_NOW), hook.function_name.c_str());
            if (!addr) {
                LOGE("Function %s not found in %s", hook.function_name.c_str(), hook.library_name.c_str());
                continue;
            }
            target_addr = reinterpret_cast<uintptr_t>(addr);
        }
        if (!hook_function(target_addr, hook.new_func, hook.orig_func)) {
            LOGE("Failed to hook %s in %s", hook.function_name.c_str(), hook.library_name.c_str());
        }
    }

    for (const auto& bypass : g_bypasses) {
        uintptr_t target_addr = 0;
        if (!bypass.pattern.pattern.empty()) {
            target_addr = find_pattern_in_library(bypass.library_name, bypass.pattern);
            if (!target_addr) {
                LOGE("Bypass pattern not found in %s", bypass.library_name.c_str());
                continue;
            }
            target_addr += bypass.patch_offset;
        } else {
            void* addr = dlsym(dlopen(bypass.library_name.c_str(), RTLD_NOW), bypass.function_name.c_str());
            if (!addr) {
                LOGE("Bypass function %s not found in %s", bypass.function_name.c_str(), bypass.library_name.c_str());
                continue;
            }
            target_addr = reinterpret_cast<uintptr_t>(addr);
        }
        if (!hook_function(target_addr, bypass.new_func, bypass.orig_func)) {
            LOGE("Failed to apply bypass %s in %s", bypass.function_name.c_str(), bypass.library_name.c_str());
        }
    }

    LOGI("[+] All patches and hooks applied.");
    return nullptr;
}

// --- INICJALIZACJA KONFIGURACJI ---
void add_hook(const HookConfig& hook) { g_hooks.push_back(hook); }
void add_patch(const PatchConfig& patch) { g_patches.push_back(patch); }
void add_bypass(const BypassConfig& bypass) { g_bypasses.push_back(bypass); }

void init_stealth_hooks() {
    add_hook({ "libc.so", "openat", reinterpret_cast<void*>(my_openat), reinterpret_cast<void**>(&orig_openat), {}, 0 });
    add_hook({ "libc.so", "fgets", reinterpret_cast<void*>(my_fgets), reinterpret_cast<void**>(&orig_fgets), {}, 0 });
}

void init_default_bypasses() {
    add_bypass({ "libanogs.so", "IsEnable", reinterpret_cast<void*>(IsEnable), reinterpret_cast<void**>(&old_IsEnable), {}, 0 });
    add_bypass({ "libanogs.so", "AnoSDKExport", reinterpret_cast<void*>(hook_AnoSDKExport), reinterpret_cast<void**>(&orig_AnoSDKExport), {}, 0 });
}

void init_default_patches() {
    // Przykładowe wzorce (trzeba dostosować do rzeczywistych bibliotek)
    add_patch({
        "libanogs.so",
        { hex_to_bytes("00 00 A0 E3 1E FF 2F E1"), {true, true, true, true, true, true, true, true}, 0 },
        hex_to_bytes("00 00 A0 E3 1E FF 2F E1"),
        0
    });
    add_patch({
        "libUE4.so",
        { hex_to_bytes("64 09 A0 E3 1E FF 2F E1"), {true, true, true, true, true, true, true, true}, 0 },
        hex_to_bytes("64 09 A0 E3 1E FF 2F E1"),
        0
    });
}

// --- JNI INTERFACE ---
static jobject (*orig_getAssets)(JNIEnv*, jobject) = nullptr;
jobject my_getAssets(JNIEnv* env, jobject thiz) {
    jobject assetMgr = orig_getAssets(env, thiz);
    static bool stealth_done = false;
    if (!stealth_done) {
        load_from_assets_stealth(env, assetMgr);
        stealth_done = true;
    }
    return assetMgr;
}

// --- JNI_ONLOAD ---
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    g_jvm = vm;
    JNIEnv* env;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    // Inicjalizacja domyślnych hooków, patch'y i bypassów
    init_stealth_hooks();
    init_default_bypasses();
    init_default_patches();

    // Hook getAssets (trigger loadera)
    uintptr_t getAssets_addr = reinterpret_cast<uintptr_t>(
        dlsym(RTLD_DEFAULT, "_ZN7android14AssetManager10getAssetsEv")
    );
    if (!getAssets_addr) {
        getAssets_addr = reinterpret_cast<uintptr_t>(
            dlsym(dlopen("libandroid_runtime.so", RTLD_NOW), "AndroidRuntime_getAssets")
        );
    }
    if (getAssets_addr) {
        hook_function(getAssets_addr, reinterpret_cast<void*>(my_getAssets), reinterpret_cast<void**>(&orig_getAssets));
    } else {
        LOGE("Failed to find getAssets address");
    }

    // Uruchom wątek patchowania
    if (pthread_create(&g_patch_thread, nullptr, game_patch_thread, nullptr) != 0) {
        LOGE("Failed to create patch thread");
    }

    LOGI("[+] StealthLoader with And64InlineHook initialized.");
    return JNI_VERSION_1_6;
}

// --- JNI_UNLOAD ---
extern "C" JNIEXPORT void JNICALL JNI_OnUnload(JavaVM* vm, void* reserved) {
    g_stop_thread = true;
    for (auto hook : g_inline_hooks) {
        unhook_function(hook);
    }
    g_inline_hooks.clear();
    if (pthread_join(g_patch_thread, nullptr) != 0) {
        LOGE("Failed to join patch thread");
    }
    LOGI("[+] StealthLoader unloaded.");
}
    if (bytehook_init(BYTEHOOK_MODE_AUTOMATIC, false) = 0) {
        LOGE("[-] BĹ‚Ä…d inicjalizacji Bytehook");
        return JNI_ERR;
    }

    bytehook_hook_all("libc.so", "openat", (void*)my_openat, (void**)&orig_openat, nullptr);
    bytehook_hook_all("libc.so", "dlopen", (void*)my_dlopen, (void**)&orig_dlopen, nullptr);
    bytehook_hook_all("libc.so", "android_dlopen_ext", (void*)my_android_dlopen_ext, (void**)&orig_android_dlopen_ext, nullptr);
    bytehook_hook_all("libc.so", "fopen", (void*)my_fopen, (void**)&orig_fopen, nullptr);
    bytehook_hook_all("libdl.so", "dlsym", (void*)my_dlsym, (void**)&orig_dlsym, nullptr);
    bytehook_hook_all("libc.so", "ptrace", (void*)my_ptrace, (void**)&orig_ptrace, nullptr);

    LOGI("[+] Hooki zarejestrowane.");
    return JNI_VERSION_1_6;
}
