#include <jni.h>
#include <string>
#include <vector>
#include <map>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <cstdarg>
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
#include <inttypes.h>
#include <sys/prctl.h>

#if __has_include(<sys/ashmem.h>)
#include <sys/ashmem.h>
#define HAS_ASHMEM 1
#else
#define HAS_ASHMEM 0
#endif

// --- CONFIG ---
#define LOG_TAG "StealthFix"
#define DEBUG_MODE 0  // 0 = production, 1 = debug logs

#if DEBUG_MODE
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...)
#define LOGE(...)
#endif

// Page macros
#define PAGE_SIZE sysconf(_SC_PAGESIZE)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define PAGE_START(addr) ((uintptr_t)(addr) & PAGE_MASK)

constexpr uint8_t XOR_KEY = 0x55;

// --- INLINE HOOK STRUCT ---
typedef struct {
    uintptr_t targetAddr;
    uintptr_t replaceAddr;
    uint8_t backup[16];
    int enabled;
} InlineHook;

// --- HELPER FUNCTIONS ---
std::string decrypt_string(const std::vector<uint8_t>& cipher) {
    std::string output;
    for (uint8_t b : cipher) {
        output += static_cast<char>(b ^ XOR_KEY);
    }
    return output;
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    std::string cleaned_hex;
    std::remove_copy_if(hex.begin(), hex.end(), std::back_inserter(cleaned_hex),
        [](char c) { return std::isspace(c); });
    for (size_t i = 0; i < cleaned_hex.length(); i += 2) {
        std::string byte_str = cleaned_hex.substr(i, 2);
        bytes.push_back(static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16)));
    }
    return bytes;
}

// --- GLOBALS ---
static JavaVM* g_jvm = nullptr;
static pthread_t g_patch_thread;
static volatile bool g_stop_thread = false;
static std::mutex g_memory_mutex;
static std::map<std::string, uintptr_t> g_library_bases;
static std::vector<InlineHook*> g_inline_hooks;
static bool g_frida_loaded = false;
static std::string g_lib_dir; // Katalog z bibliotekami (lib/arm64-v8a/)

static std::vector<std::string> g_blacklist = {
    decrypt_string({0x1B, 0x10, 0x07, 0x04, 0x00, 0x1E, 0x07}), // "gadget"
    decrypt_string({0x1C, 0x11, 0x0E, 0x0D, 0x2F, 0x06, 0x21}), // "gum-js"
    decrypt_string({0x28, 0x21, 0x26, 0x20, 0x1E, 0x21, 0x28}), // "agent.so"
    decrypt_string({0x2B, 0x20, 0x27, 0x20, 0x26, 0x21, 0x28, 0x2D}), // "linjector"
    decrypt_string({0x2D, 0x20, 0x27, 0x21, 0x28, 0x26}), // "magisk"
    decrypt_string({0x1F, 0x10, 0x07, 0x04, 0x0D, 0x00}), // "frida-server"
};

// --- GET LIBRARY DIRECTORY (Pobiera ścieżkę do lib/arm64-v8a/) ---
std::string get_library_dir() {
    if (!g_lib_dir.empty()) {
        return g_lib_dir;
    }

    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGE("Failed to open /proc/self/maps");
        return "";
    }

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "stealth_fix.so")) {
            char* path_start = strchr(line, '/');
            if (path_start) {
                char* path_end = strrchr(path_start, '/');
                if (path_end) {
                    *path_end = '\0';
                    g_lib_dir = path_start;
                    fclose(fp);
                    return g_lib_dir;
                }
            }
        }
    }
    fclose(fp);
    return "";
}

// --- MEMORY UTILITIES ---
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
            sscanf(line, "%" SCNxPTR "-%*lx", &base);
            break;
        }
    }
    fclose(fp);

    if (base) {
        g_library_bases[lib_name] = base;
    }
    return base;
}

bool change_memory_protection(void* addr, int prot) {
    uintptr_t page_start = PAGE_START(reinterpret_cast<uintptr_t>(addr));
    return mprotect(reinterpret_cast<void*>(page_start), PAGE_SIZE, prot) == 0;
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

// --- INLINE HOOK IMPLEMENTATION ---
int InlineHook_init(InlineHook* hook, uintptr_t targetAddr, uintptr_t replaceAddr) {
    if (!hook) return -1;
    hook->targetAddr = targetAddr;
    hook->replaceAddr = replaceAddr;
    hook->enabled = 0;

#if defined(__aarch64__)
    memcpy(hook->backup, (void*)targetAddr, 8);
#elif defined(__arm__)
    memcpy(hook->backup, (void*)targetAddr, 8);
#elif defined(__i386__)
    memcpy(hook->backup, (void*)targetAddr, 5);
#endif
    return 0;
}

int InlineHook_enable(InlineHook* hook) {
    if (!hook || hook->enabled) return -1;

    uintptr_t pageStart = hook->targetAddr & ~(PAGE_SIZE - 1);
    if (mprotect((void*)pageStart, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        return -1;
    }

#if defined(__aarch64__)
    uint32_t patch[2] = { 0x58000051, 0xD61F0220 };
    memcpy((void*)hook->targetAddr, patch, 8);
    uintptr_t* trampoline = (uintptr_t*)mmap(NULL, 16, PROT_READ | PROT_WRITE | PROT_EXEC,
                                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (trampoline == MAP_FAILED) {
        mprotect((void*)pageStart, PAGE_SIZE, PROT_READ | PROT_EXEC);
        return -1;
    }
    *trampoline = hook->replaceAddr;
    *(uintptr_t*)(hook->targetAddr + 8) = (uintptr_t)trampoline;
#elif defined(__arm__)
    uint32_t patch[2] = { 0xE51FF004, static_cast<uint32_t>(hook->replaceAddr) };
    memcpy((void*)hook->targetAddr, patch, 8);
#elif defined(__i386__)
    uint8_t patch[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
    uint32_t* offset_ptr = (uint32_t*)(patch + 1);
    *offset_ptr = hook->replaceAddr - (hook->targetAddr + 5);
    memcpy((void*)hook->targetAddr, patch, 5);
#endif

    hook->enabled = 1;
    mprotect((void*)pageStart, PAGE_SIZE, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char*)hook->targetAddr, (char*)(hook->targetAddr + 16));
    return 0;
}

int InlineHook_disable(InlineHook* hook) {
    if (!hook || !hook->enabled) return -1;

    uintptr_t pageStart = hook->targetAddr & ~(PAGE_SIZE - 1);
    if (mprotect((void*)pageStart, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        return -1;
    }

#if defined(__aarch64__) || defined(__arm__)
    memcpy((void*)hook->targetAddr, hook->backup, 8);
#elif defined(__i386__)
    memcpy((void*)hook->targetAddr, hook->backup, 5);
#endif

    hook->enabled = 0;
    mprotect((void*)pageStart, PAGE_SIZE, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char*)hook->targetAddr, (char*)(hook->targetAddr + 16));
    return 0;
}

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

// --- ANTI-DETECTION HOOKS ---
static long (*orig_syscall)(long number, ...) = nullptr;
long my_syscall(long number, ...) {
    if (number == __NR_ptrace) {
        va_list args;
        va_start(args, number);
        long request = va_arg(args, long);
        va_end(args);
        if (request == PTRACE_TRACEME) {
            return orig_syscall(number, args); // Pozwól Fridzie na podpięcie
        }
        return -EPERM; // Blokuj inne operacje ptrace
    }
    va_list args;
    va_start(args, number);
    long result = orig_syscall(number, args);
    va_end(args);
    return result;
}

static int (*orig_prctl)(int option, ...) = nullptr;
int my_prctl(int option, ...) {
    if (option == PR_SET_DUMPABLE) {
        return -EINVAL; // Blokuj dumpowanie pamięci
    }
    va_list args;
    va_start(args, option);
    int result = orig_prctl(option, args);
    va_end(args);
    return result;
}

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
        return my_fgets(s, size, stream); // Pomijaj linie z blacklisty
    }
    return result;
}

static ssize_t (*orig_readlink)(const char*, char*, size_t) = nullptr;
ssize_t my_readlink(const char* pathname, char* buf, size_t bufsiz) {
    if (strstr(pathname, "/proc/self/status")) {
        const char* fake_status =
            "Name:\tmyapp\n"
            "State:\tS (sleeping)\n"
            "Tgid:\t12345\n"
            "Pid:\t12345\n"
            "PPid:\t1234\n"
            "TracerPid:\t0\n"; // Ukryj TracerPid
        strncpy(buf, fake_status, bufsiz - 1);
        buf[bufsiz - 1] = '\0';
        return strlen(fake_status);
    }
    return orig_readlink(pathname, buf, bufsiz);
}

static int (*orig_sigaction)(int, const struct sigaction*, struct sigaction*) = nullptr;
int my_sigaction(int signum, const struct sigaction* act, struct sigaction* oldact) {
    if (signum == SIGSEGV || signum == SIGBUS || signum == SIGABRT) {
        struct sigaction ignore_act = {0};
        ignore_act.sa_handler = SIG_IGN;
        return orig_sigaction(signum, &ignore_act, oldact); // Blokuj tombstone
    }
    return orig_sigaction(signum, act, oldact);
}

// --- FRIDA GADGET LOADING (Z lib/arm64-v8a/) ---
void load_frida_gadget() {
    if (g_frida_loaded) return;
    g_frida_loaded = true;

    std::string lib_dir = get_library_dir();
    if (lib_dir.empty()) {
        LOGE("Failed to get library directory");
        return;
    }

    // Próba 1: Załaduj libfrida-gadget.so (jeśli istnieje)
    std::vector<std::string> frida_paths = {
        lib_dir + "/libfrida-gadget.so",      // Oryginalna nazwa
        lib_dir + "/libonyx-android-jni.so",  // Przemianowana nazwa (z Twojego zrzutu)
        lib_dir + "/libSignatureKiller.so"    // Inna przemianowana nazwa
    };

    for (const auto& frida_path : frida_paths) {
        int fd = open(frida_path.c_str(), O_RDONLY);
        if (fd == -1) continue;

        struct stat st;
        if (fstat(fd, &st) != 0) {
            close(fd);
            continue;
        }

        void* addr = mmap(nullptr, st.st_size, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
        if (addr == MAP_FAILED) {
            close(fd);
            continue;
        }

        void* handle = dlopen(addr, RTLD_NOW | RTLD_GLOBAL);
        if (!handle) {
            LOGE("Failed to dlopen %s: %s", frida_path.c_str(), dlerror());
            munmap(addr, st.st_size);
            close(fd);
            continue;
        }

        // Wyczyszczenie nagłówka ELF (ukrycie przed skanerami)
        struct link_map* map;
        if (dlinfo(handle, RTLD_DI_LINKMAP, &map) == 0) {
            wipe_elf_header(reinterpret_cast<void*>(map->l_addr));
        }

        munmap(addr, st.st_size);
        close(fd);
        LOGI("Frida gadget loaded successfully from %s!", frida_path.c_str());
        return;
    }

    LOGE("Failed to load Frida gadget from any path in %s", lib_dir.c_str());
}

// --- JNI_ONLOAD ---
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    g_jvm = vm;
    JNIEnv* env;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    // Pobierz katalog z bibliotekami
    get_library_dir();

    // Załaduj Frida Gadget (z lib/arm64-v8a/)
    load_frida_gadget();

    // Inicjalizuj hooki anty-detekcyjne
    void* syscall_addr = dlsym(RTLD_DEFAULT, "syscall");
    if (syscall_addr) {
        hook_function(reinterpret_cast<uintptr_t>(syscall_addr),
                     reinterpret_cast<void*>(my_syscall),
                     reinterpret_cast<void**>(&orig_syscall));
    }

    void* prctl_addr = dlsym(RTLD_DEFAULT, "prctl");
    if (prctl_addr) {
        hook_function(reinterpret_cast<uintptr_t>(prctl_addr),
                     reinterpret_cast<void*>(my_prctl),
                     reinterpret_cast<void**>(&orig_prctl));
    }

    void* openat_addr = dlsym(RTLD_DEFAULT, "openat");
    if (openat_addr) {
        hook_function(reinterpret_cast<uintptr_t>(openat_addr),
                     reinterpret_cast<void*>(my_openat),
                     reinterpret_cast<void**>(&orig_openat));
    }

    void* fgets_addr = dlsym(RTLD_DEFAULT, "fgets");
    if (fgets_addr) {
        hook_function(reinterpret_cast<uintptr_t>(fgets_addr),
                     reinterpret_cast<void*>(my_fgets),
                     reinterpret_cast<void**>(&orig_fgets));
    }

    void* readlink_addr = dlsym(RTLD_DEFAULT, "readlink");
    if (readlink_addr) {
        hook_function(reinterpret_cast<uintptr_t>(readlink_addr),
                     reinterpret_cast<void*>(my_readlink),
                     reinterpret_cast<void**>(&orig_readlink));
    }

    void* sigaction_addr = dlsym(RTLD_DEFAULT, "sigaction");
    if (sigaction_addr) {
        hook_function(reinterpret_cast<uintptr_t>(sigaction_addr),
                     reinterpret_cast<void*>(my_sigaction),
                     reinterpret_cast<void**>(&orig_sigaction));
    }

    LOGI("StealthFix loaded successfully!");
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT void JNICALL JNI_OnUnload(JavaVM* vm, void* reserved) {
    g_stop_thread = true;
    if (g_patch_thread) {
        pthread_join(g_patch_thread, nullptr);
    }

    for (auto hook : g_inline_hooks) {
        unhook_function(hook);
    }
    g_inline_hooks.clear();

    LOGI("StealthFix unloaded");
}
