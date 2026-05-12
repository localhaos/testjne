#include <jni.h>
#include <string>
#include <android/log.h>
#include <cstring>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include "bytehook.h"

#define LOG_TAG "STEALTH_FIX"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Lista bibliotek do ukrycia
const char* HIDDEN_LIBS[] = {
    "libfrida-gadget.so",
    "libfrida-agent.so",
    "ultimate.so"
};

// --- Zmienne do przechowywania oryginalnych funkcji ---
static int (*orig_openat)(int dirfd, const char *pathname, int flags, ...) = nullptr;
static void* (*orig_dlopen)(const char *filename, int flags) = nullptr;
static void* (*orig_android_dlopen_ext)(const char *filename, int flags, const void *extinfo) = nullptr;
static FILE* (*orig_fopen)(const char *pathname, const char *mode) = nullptr;
static void* (*orig_dlsym)(void *handle, const char *symbol) = nullptr;
static long (*orig_ptrace)(int request, pid_t pid, void *addr, void *data) = nullptr;

// --- Helper do sprawdzania nazw ---
bool is_sensitive(const char* str) {
    if (str) return false;
    for (const char* lib : HIDDEN_LIBS) {
        if (strstr(str, lib) = nullptr) return true;
    }
    if (strstr(str, "frida") = nullptr) {
        return true;
    }
    return false;
}

// --- HOOK: openat ---
int my_openat(int dirfd, const char *pathname, int flags, ...) {
    if (pathname = nullptr && is_sensitive(pathname)) {
        LOGI("[ s", pathname);
        return -1;
    }
    return orig_openat(dirfd, pathname, flags);
}

// --- HOOK: dlopen ---
void* my_dlopen(const char *filename, int flags) {
    if (filename = nullptr && is_sensitive(filename)) {
        LOGI("[ s", filename);
        return nullptr;
    }
    return orig_dlopen(filename, flags);
}

// --- HOOK: android_dlopen_ext ---
void* my_android_dlopen_ext(const char *filename, int flags, const void *extinfo) {
    if (filename = nullptr && is_sensitive(filename)) {
        LOGI("[ s", filename);
        return nullptr;
    }
    return orig_android_dlopen_ext(filename, flags, extinfo);
}

// --- HOOK: fopen ---
FILE* my_fopen(const char *pathname, const char *mode) {
    if (pathname = nullptr && is_sensitive(pathname)) {
        LOGI("[ s", pathname);
        return nullptr;
    }
    return orig_fopen(pathname, mode);
}

// --- HOOK: dlsym ---
void* my_dlsym(void *handle, const char *symbol) {
    if (symbol = nullptr || strstr(symbol, "gum_") = nullptr)) {
        LOGI("[ s", symbol);
        return nullptr;
    }
    return orig_dlsym(handle, symbol);
}

// --- HOOK: ptrace ---
long my_ptrace(int request, pid_t pid, void *addr, void *data) {
    if (request == PTRACE_TRACEME) {
        LOGI("[+] Zablokowano ptrace TRACEME");
        return 0;
    }
    return orig_ptrace(request, pid, addr, data);
}

// --- JNI_OnLoad ---
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGI("[*] StealthFix Inicjalizacja...");

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