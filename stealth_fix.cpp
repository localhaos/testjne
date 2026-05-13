#include <jni.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <memory>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <random>
#include <ctime>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstdarg>
#include <inttypes.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>

#include <dlfcn.h>
#include <link.h>

#include <android/log.h>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>

#if __has_include(<sys/ashmem.h>)
#include <sys/ashmem.h>
#define HAS_ASHMEM 1
#else
#define HAS_ASHMEM 0
#endif

// ------------------------------------------------------------
// CONFIG
// ------------------------------------------------------------

#define LOG_TAG "SystemUtils"
#define DEBUG_MODE 0

#if DEBUG_MODE
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...)
#define LOGE(...)
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define PAGE_MASK (~(PAGE_SIZE - 1))
#define PAGE_START(addr) ((uintptr_t)(addr) & PAGE_MASK)

constexpr uint8_t XOR_KEY = 0x55;

// ------------------------------------------------------------
// HELPERS
// ------------------------------------------------------------

std::string decrypt_string(std::initializer_list<uint8_t> cipher) {
    std::string output;

    for (uint8_t b : cipher) {
        if (b == 0x00)
            break;

        output += static_cast<char>(b ^ XOR_KEY);
    }

    return output;
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;

    std::istringstream iss(hex);
    std::string byte_str;

    while (iss >> byte_str) {
        bytes.push_back(
            static_cast<uint8_t>(
                strtoul(byte_str.c_str(), nullptr, 16)
            )
        );
    }

    return bytes;
}

std::string generate_random_name() {
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

// ------------------------------------------------------------
// GLOBALS
// ------------------------------------------------------------

static JavaVM* g_jvm = nullptr;
static pthread_t g_patch_thread;
static volatile bool g_stop_thread = false;

static std::mutex g_memory_mutex;
static std::map<std::string, uintptr_t> g_library_bases;

static std::vector<std::string> g_blacklist = {
    "frida",
    "gadget",
    "gum-js",
    "agent.so",
    "linjector",
    "magisk",
    "frida-server"
};

// ------------------------------------------------------------
// MEMORY
// ------------------------------------------------------------

uintptr_t find_library_base(const char* lib_name) {
    auto it = g_library_bases.find(lib_name);

    if (it != g_library_bases.end()) {
        return it->second;
    }

    FILE* fp = fopen("/proc/self/maps", "r");

    if (!fp)
        return 0;

    char line[1024];
    uintptr_t base = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, lib_name)) {

            sscanf(
                line,
                "%" SCNxPTR "-%*lx",
                &base
            );

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
    uintptr_t page_start =
        PAGE_START(reinterpret_cast<uintptr_t>(addr));

    return mprotect(
        reinterpret_cast<void*>(page_start),
        PAGE_SIZE,
        prot
    ) == 0;
}

// ------------------------------------------------------------
// INLINE HOOK
// ------------------------------------------------------------

typedef struct {
    uintptr_t targetAddr;
    uintptr_t replaceAddr;
    uint8_t backup[16];
    int enabled;
} InlineHook;

int InlineHook_init(
    InlineHook* hook,
    uintptr_t targetAddr,
    uintptr_t replaceAddr
) {
    if (!hook)
        return -1;

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
    if (!hook || hook->enabled)
        return -1;

    uintptr_t pageStart =
        hook->targetAddr & ~(PAGE_SIZE - 1);

    if (mprotect(
            (void*)pageStart,
            PAGE_SIZE,
            PROT_READ | PROT_WRITE | PROT_EXEC
        ) != 0) {
        return -1;
    }

#if defined(__aarch64__)

    uint32_t patch[2] = {
        0x58000051,
        0xD61F0220
    };

    memcpy((void*)hook->targetAddr, patch, 8);

    *(uintptr_t*)(hook->targetAddr + 8) =
        hook->replaceAddr;

#elif defined(__arm__)

    uint32_t patch[2] = {
        0xE51FF004,
        static_cast<uint32_t>(hook->replaceAddr)
    };

    memcpy((void*)hook->targetAddr, patch, 8);

#elif defined(__i386__)

    uint8_t patch[5] = {
        0xE9,
        0x00,
        0x00,
        0x00,
        0x00
    };

    *(uint32_t*)(patch + 1) =
        hook->replaceAddr - (hook->targetAddr + 5);

    memcpy((void*)hook->targetAddr, patch, 5);

#endif

    hook->enabled = 1;

    mprotect(
        (void*)pageStart,
        PAGE_SIZE,
        PROT_READ | PROT_EXEC
    );

    __builtin___clear_cache(
        (char*)hook->targetAddr,
        (char*)(hook->targetAddr + 16)
    );

    return 0;
}

// ------------------------------------------------------------
// BLACKLIST
// ------------------------------------------------------------

bool contains_blacklist(const char* str) {
    if (!str)
        return false;

    for (const auto& keyword : g_blacklist) {
        if (strstr(str, keyword.c_str())) {
            return true;
        }
    }

    return false;
}

// ------------------------------------------------------------
// HOOKS
// ------------------------------------------------------------

static int (*orig_openat)(
    int,
    const char*,
    int,
    mode_t
) = nullptr;

int my_openat(
    int dirfd,
    const char* pathname,
    int flags,
    mode_t mode
) {
    if (contains_blacklist(pathname)) {
        errno = ENOENT;
        return -1;
    }

    return orig_openat(
        dirfd,
        pathname,
        flags,
        mode
    );
}

static char* (*orig_fgets)(
    char*,
    int,
    FILE*
) = nullptr;

char* my_fgets(
    char* s,
    int size,
    FILE* stream
) {
    char* result =
        orig_fgets(s, size, stream);

    if (result && contains_blacklist(result)) {
        return my_fgets(s, size, stream);
    }

    return result;
}

// ------------------------------------------------------------
// PATCH THREAD
// ------------------------------------------------------------

void* game_patch_thread(void*) {

    while (!g_stop_thread) {
        usleep(500000);
    }

    return nullptr;
}

// ------------------------------------------------------------
// ASSET LOAD
// ------------------------------------------------------------

void* load_from_assets_stealth(
    JNIEnv* env,
    jobject assetMgr
) {
    AAssetManager* mgr =
        AAssetManager_fromJava(env, assetMgr);

    if (!mgr)
        return nullptr;

    AAssetDir* dir =
        AAssetManager_openDir(mgr, "");

    if (!dir)
        return nullptr;

    const char* fileName;

    while ((fileName =
                AAssetDir_getNextFileName(dir)) != nullptr) {

        LOGI("Asset: %s", fileName);
    }

    AAssetDir_close(dir);

    return nullptr;
}

// ------------------------------------------------------------
// JNI
// ------------------------------------------------------------

extern "C"
JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM* vm, void* reserved) {

    g_jvm = vm;

    JNIEnv* env;

    if (vm->GetEnv(
            reinterpret_cast<void**>(&env),
            JNI_VERSION_1_6
        ) != JNI_OK) {
        return JNI_ERR;
    }

    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        return JNI_ERR;
    }

    srand(time(nullptr));

    if (pthread_create(
            &g_patch_thread,
            nullptr,
            game_patch_thread,
            nullptr
        ) != 0) {
        return JNI_ERR;
    }

    LOGI("JNI_OnLoad success");

    return JNI_VERSION_1_6;
}

extern "C"
JNIEXPORT void JNICALL
JNI_OnUnload(JavaVM* vm, void* reserved) {

    g_stop_thread = true;

    pthread_join(g_patch_thread, nullptr);

    LOGI("JNI_OnUnload");
}
