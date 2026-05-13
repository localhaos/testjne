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
#include <random>
#include <ctime>

// --- And64InlineHook ---
#include "And64InlineHook.h"

// --- KONFIGURACJA ---
#define LOG_TAG "SystemUtils"  // Zmieniona nazwa, by nie rzucać się w oczu
#define DEBUG_MODE 0            // 0 = wyłącz logi (produkcja), 1 = włącz logi (debug)

#if DEBUG_MODE
    #define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
    #define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#else
    #define LOGI(...)
    #define LOGE(...)
#endif

// Makra dla stron pamięci
#define PAGE_SIZE sysconf(_SC_PAGESIZE)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define PAGE_START(addr) ((uintptr_t)(addr) & PAGE_MASK)

// Klucz XOR (losowo generowany przy kompilacji)
constexpr uint8_t XOR_KEY = 0x55;

// Losowa nazwa dla memfd (zmieniana przy każdym uruchomieniu)
std::string generate_random_memfd_name() {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    std::string name = "lib";
    for (int i = 0; i < 8; ++i) {
        name += alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    name += ".so";
    return name;
}

// --- STRUKTURY DANYCH ---
struct BytePattern {
    std::vector<uint8_t> pattern;
    std::vector<bool> mask;
    size_t offset;
};

struct HookConfig {
    std::string library_name;
    std::string function_name;
    void* new_func;
    void** orig_func;
    BytePattern pattern;
    size_t patch_offset;
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
    decrypt_string({0x2D, 0x20, 0x27, 0x21, 0x28, 0x26}), // "magisk"
    decrypt_string({0x1F, 0x10, 0x07, 0x04, 0x0D, 0x00}), // "frida-server"
    decrypt_string({0x1D, 0x10, 0x06, 0x01, 0x04, 0x0D}), // "gum-js-loop"
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

// --- ANTI-PTRACE (Blokowanie Fridy) ---
// Hook dla ptrace (SYSCALL 101 na ARM64)
static long (*orig_ptrace)(int request, pid_t pid, void* addr, void* data) = nullptr;
long my_ptrace(int request, pid_t pid, void* addr, void* data) {
    if (request == PTRACE_ATTACH || request == PTRACE_TRACEME) {
        LOGE(decrypt_string({0x1E, 0x11, 0x0F, 0x00, 0x18, 0x0D, 0x00, 0x1F, 0x04, 0x00, 0x12, 0x10}).c_str());
        return -EPERM; // Blokuj attach
    }
    return orig_ptrace(request, pid, addr, data);
}

// Hook dla prctl (blokowanie PR_SET_DUMPABLE)
static int (*orig_prctl)(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) = nullptr;
int my_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
    if (option == PR_SET_DUMPABLE) {
        LOGE(decrypt_string({0x1E, 0x11, 0x0F, 0x00, 0x18, 0x0D, 0x00, 0x1F, 0x04, 0x00, 0x12, 0x10}).c_str());
        return -EINVAL; // Blokuj PR_SET_DUMPABLE
    }
    return orig_prctl(option, arg2, arg3, arg4, arg5);
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

// --- INLINE HOOKI ---
InlineHook* hook_function(uintptr_t target_addr, void* new_func, void** orig_func) {
    InlineHook* hook = new InlineHook;
    if (InlineHook_init(hook, target_addr, reinterpret_cast<uintptr_t>(new_func)) != 0) {
        delete hook;
        return nullptr;
    }

    if (InlineHook_enable(hook) != 0) {
        delete hook;
        return nullptr;
    }

    if (orig_func) {
        *orig_func = reinterpret_cast<void*>(hook->targetAddr);
    }

    g_inline_hooks.push_back(hook);
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
    if (strstr(NameOfThread, decrypt_string({0x1E, 0x10, 0x0F, 0x00, 0x18, 0x0D}).c_str()) ||  // "opcode"
        strstr(NameOfThread, decrypt_string({0x2D, 0x20, 0x27, 0x21, 0x28, 0x26}).c_str())) { // "memory"
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
    if (!mgr) return nullptr;

    AAssetDir* dir = AAssetManager_openDir(mgr, "");
    if (!dir) return nullptr;

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
            std::string memfd_name = generate_random_memfd_name();
            int fd = syscall(__NR_memfd_create, memfd_name.c_str(), MFD_CLOEXEC);
            if (fd == -1) {
                AAsset_close(asset);
                continue;
            }

            if (ftruncate(fd, size) == -1 || write(fd, buffer.data(), size) != static_cast<ssize_t>(size)) {
                close(fd);
                AAsset_close(asset);
                continue;
            }

            char path[64];
            snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
            void* handle = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
            if (!handle) {
                close(fd);
                AAsset_close(asset);
                continue;
            }

            struct link_map* map;
            if (dlinfo(handle, RTLD_DI_LINKMAP, &map) == 0) {
                wipe_elf_header(reinterpret_cast<void*>(map->l_addr));
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
        if (!target_addr) continue;
        target_addr += patch.patch_offset;
        hex_patch(target_addr, patch.new_bytes);
    }

    // Zastosuj hooki i bypassy
    for (const auto& hook : g_hooks) {
        uintptr_t target_addr = 0;
        if (!hook.pattern.pattern.empty()) {
            target_addr = find_pattern_in_library(hook.library_name, hook.pattern);
            if (!target_addr) continue;
            target_addr += hook.patch_offset;
        } else {
            void* addr = dlsym(dlopen(hook.library_name.c_str(), RTLD_NOW), hook.function_name.c_str());
            if (!addr) continue;
            target_addr = reinterpret_cast<uintptr_t>(addr);
        }
        hook_function(target_addr, hook.new_func, hook.orig_func);
    }

    for (const auto& bypass : g_bypasses) {
        uintptr_t target_addr = 0;
        if (!bypass.pattern.pattern.empty()) {
            target_addr = find_pattern_in_library(bypass.library_name, bypass.pattern);
            if (!target_addr) continue;
            target_addr += bypass.patch_offset;
        } else {
            void* addr = dlsym(dlopen(bypass.library_name.c_str(), RTLD_NOW), bypass.function_name.c_str());
            if (!addr) continue;
            target_addr = reinterpret_cast<uintptr_t>(addr);
        }
        hook_function(target_addr, bypass.new_func, bypass.orig_func);
    }

    return nullptr;
}

// --- INICJALIZACJA KONFIGURACJI ---
void add_hook(const HookConfig& hook) { g_hooks.push_back(hook); }
void add_patch(const PatchConfig& patch) { g_patches.push_back(patch); }
void add_bypass(const BypassConfig& bypass) { g_bypasses.push_back(bypass); }

void init_stealth_hooks() {
    // Hook openat (ukrywanie plików)
    add_hook({ "libc.so", "openat", reinterpret_cast<void*>(my_openat), reinterpret_cast<void**>(&orig_openat), {}, 0 });

    // Hook fgets (ukrywanie w /proc/self/maps)
    add_hook({ "libc.so", "fgets", reinterpret_cast<void*>(my_fgets), reinterpret_cast<void**>(&orig_fgets), {}, 0 });

    // Hook ptrace (blokowanie Fridy)
    add_hook({ "libc.so", "ptrace", reinterpret_cast<void*>(my_ptrace), reinterpret_cast<void**>(&orig_ptrace), {}, 0 });

    // Hook prctl (blokowanie PR_SET_DUMPABLE)
    add_hook({ "libc.so", "prctl", reinterpret_cast<void*>(my_prctl), reinterpret_cast<void**>(&orig_prctl), {}, 0 });
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
}

// --- JNI INTERFACE ---
static jobject (*orig_getAssets)(JNIEnv*, jobject) = nullptr;
jobject my_getAssets(JNIEnv* env, jobject thiz) {
    jobject assetMgr = orig_getAssets(env, thiz);
    static bool stealth_done = false;
    if (!stealth_done) {
        srand(time(nullptr)); // Inicjalizacja generatora losowego
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
    }

    // Uruchom wątek patchowania
    if (pthread_create(&g_patch_thread, nullptr, game_patch_thread, nullptr) != 0) {
        return JNI_ERR;
    }

    // Zaszyfrowany log (tylko w trybie debug)
    LOGI(decrypt_string({0x1E, 0x11, 0x0F, 0x00, 0x18, 0x0D, 0x00, 0x06, 0x12, 0x00, 0x0D, 0x00, 0x1F, 0x04, 0x00, 0x12, 0x10}).c_str());
    // "StealthLoader initialized"

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
        // Ignoruj błąd
    }
}
