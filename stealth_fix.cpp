#include <jni.h>
#include <string>
#include <android/log.h>
#include <cstring>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <vector>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include "bytehook.h"

// --- LOGI/LOGE (ukryte pod systemowym tagiem) ---
#define LOG_TAG "AndroidRuntime"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// --- Globalne zmienne ---
static JavaVM* g_jvm = nullptr;
static jobject g_application_context = nullptr;
static std::vector<unsigned char> g_frida_so_buffer;
static bool g_asset_loaded = false;

// --- Lista ukrywanych bibliotek/symboli ---
const char* HIDDEN_LIBS[] = {
    "libfrida-gadget.so",
    "libfrida-agent.so",
    "frida",
    "gum_",
    "ultimate.so"
};

// --- Oryginalne funkcje (do hooków) ---
static int (*orig_openat)(int dirfd, const char *pathname, int flags, mode_t mode) = nullptr;
static void* (*orig_dlopen)(const char *filename, int flags) = nullptr;
static void* (*orig_android_dlopen_ext)(const char *filename, int flags, const void *extinfo) = nullptr;
static FILE* (*orig_fopen)(const char *pathname, const char *mode) = nullptr;
static void* (*orig_dlsym)(void *handle, const char *symbol) = nullptr;
static long (*orig_ptrace)(int request, pid_t pid, void *addr, void *data) = nullptr;
static AAsset* (*orig_AAssetManager_open)(AAssetManager* mgr, const char* filename, int mode) = nullptr;
static void (*orig_AndroidRuntime_start)(void* thread, const char* str) = nullptr;
static jobject (*orig_Context_getAssets)(JNIEnv* env, jobject thiz) = nullptr;
static void (*orig_LibraryLoader_loadLibrary)(JNIEnv* env, jclass clazz, jstring libraryName) = nullptr;

// --- Helper: Czy string zawiera ukrywaną nazwę? ---
bool is_sensitive(const char* str) {
    if (!str) return false;
    for (const char* lib : HIDDEN_LIBS) {
        if (strstr(str, lib) != nullptr) {
            return true;
        }
    }
    if (strstr(str, "android.properties") != nullptr) {
        return false; // Wyklucz nasz plik
    }
    return false;
}

// --- Helper: Ładowanie pliku z assets do bufora ---
bool load_asset_to_buffer(JNIEnv* env, AAssetManager* assetManager, const char* filename, std::vector<unsigned char>& buffer) {
    AAsset* asset = AAssetManager_open(assetManager, filename, AASSET_MODE_BUFFER);
    if (!asset) {
        LOGE("[-] Nie znaleziono pliku: %s", filename);
        return false;
    }

    size_t size = AAsset_getLength(asset);
    buffer.resize(size);
    AAsset_read(asset, buffer.data(), size);
    AAsset_close(asset);

    LOGI("[+] Załadowano %s (%zu bajtów)", filename, size);
    return true;
}

// --- Helper: Mapowanie bufora do pamięci ---
void* load_buffer_as_library(const std::vector<unsigned char>& buffer) {
    void* mem = mmap(nullptr, buffer.size(), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        LOGE("[-] Błąd mmap");
        return nullptr;
    }
    memcpy(mem, buffer.data(), buffer.size());
    return mem;
}

// --- HOOK: Context.getAssets (do pobrania AssetManager) ---
jobject my_Context_getAssets(JNIEnv* env, jobject thiz) {
    if (!g_application_context) {
        // Zapisz pierwszy Context, który dostaniemy (powinien być Application)
        env->GetJavaVM(&g_jvm);
        g_application_context = env->NewGlobalRef(thiz);
    }

    jobject assetManager = orig_Context_getAssets(env, thiz);

    // Ładuj android.properties, jeśli nie został jeszcze załadowany
    if (!g_asset_loaded && g_application_context) {
        jclass contextClass = env->GetObjectClass(g_application_context);
        jmethodID getAssetsMethod = env->GetMethodID(contextClass, "getAssets", "()Landroid/content/res/AssetManager;");
        jobject assetManagerJava = env->CallObjectMethod(g_application_context, getAssetsMethod);
        AAssetManager* assetManager = AAssetManager_fromJava(env, assetManagerJava);

        if (load_asset_to_buffer(env, assetManager, "android.properties", g_frida_so_buffer)) {
            g_asset_loaded = true;
            LOGI("[+] android.properties załadowany do bufora!");
        }
    }

    return assetManager;
}

// --- HOOK: openat ---
int my_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
    if (pathname != nullptr && is_sensitive(pathname)) {
        LOGI("[+] Zablokowano openat: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    return orig_openat(dirfd, pathname, flags, mode);
}

// --- HOOK: dlopen ---
void* my_dlopen(const char *filename, int flags) {
    if (filename != nullptr) {
        if (strstr(filename, "libfrida-gadget.so") != nullptr) {
            LOGI("[+] Przekierowuję libfrida-gadget.so → android.properties");
            if (!g_frida_so_buffer.empty()) {
                return load_buffer_as_library(g_frida_so_buffer);
            }
            return nullptr;
        }
        if (is_sensitive(filename)) {
            LOGI("[+] Zablokowano dlopen: %s", filename);
            return nullptr;
        }
    }
    return orig_dlopen(filename, flags);
}

// --- HOOK: android_dlopen_ext ---
void* my_android_dlopen_ext(const char *filename, int flags, const void *extinfo) {
    if (filename != nullptr && is_sensitive(filename)) {
        LOGI("[+] Zablokowano android_dlopen_ext: %s", filename);
        return nullptr;
    }
    return orig_android_dlopen_ext(filename, flags, extinfo);
}

// --- HOOK: fopen ---
FILE* my_fopen(const char *pathname, const char *mode) {
    if (pathname != nullptr && is_sensitive(pathname)) {
        LOGI("[+] Zablokowano fopen: %s", pathname);
        return nullptr;
    }
    return orig_fopen(pathname, mode);
}

// --- HOOK: dlsym ---
void* my_dlsym(void *handle, const char *symbol) {
    if (symbol != nullptr) {
        if (strstr(symbol, "gum_") != nullptr) {
            LOGI("[+] Przekierowuję symbol gum_*: %s", symbol);
            return dlsym(handle, "dummy_symbol");
        }
        if (is_sensitive(symbol)) {
            LOGI("[+] Zablokowano dlsym: %s", symbol);
            return nullptr;
        }
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

// --- HOOK: AAssetManager_open ---
AAsset* my_AAssetManager_open(AAssetManager* mgr, const char* filename, int mode) {
    if (filename != nullptr && strstr(filename, "android.properties") != nullptr) {
        LOGI("[+] Ukrywam android.properties w AAssetManager");
        return nullptr;
    }
    return orig_AAssetManager_open(mgr, filename, mode);
}

// --- HOOK: LibraryLoader.loadLibrary (dla WebView/Chromium) ---
void my_LibraryLoader_loadLibrary(JNIEnv* env, jclass clazz, jstring libraryName) {
    const char* libName = env->GetStringUTFChars(libraryName, nullptr);
    if (libName != nullptr) {
        if (strstr(libName, "frida") != nullptr || strstr(libName, "gum_") != nullptr) {
            LOGI("[+] Zablokowano ładowanie biblioteki WebView: %s", libName);
            env->ReleaseStringUTFChars(libraryName, libName);
            return;
        }
    }
    if (libName) env->ReleaseStringUTFChars(libraryName, libName);
    return orig_LibraryLoader_loadLibrary(env, clazz, libraryName);
}

// --- JNI_OnLoad ---
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGI("[*] StealthFix: JNI_OnLoad");

    JNIEnv* env;
    vm->GetEnv((void**)&env, JNI_VERSION_1_6);

    // --- 1. Inicjalizuj Bytehook ---
    if (bytehook_init(BYTEHOOK_MODE_AUTOMATIC, false) != 0) {
        LOGE("[-] Błąd inicjalizacji Bytehook");
        return JNI_ERR;
    }

    // --- 2. Hookuj Context.getAssets (aby pobrać AssetManager) ---
    jclass contextClass = env->FindClass("android/content/Context");
    jmethodID getAssetsMethod = env->GetMethodID(contextClass, "getAssets", "()Landroid/content/res/AssetManager;");
    bytehook_hook_single(
        env->GetJavaVM(),
        contextClass,
        getAssetsMethod,
        (void*)my_Context_getAssets,
        (void**)&orig_Context_getAssets,
        nullptr
    );

    // --- 3. Hookuj funkcje systemowe ---
    bytehook_hook_all("libc.so", "openat", (void*)my_openat, (void**)&orig_openat, nullptr);
    bytehook_hook_all("libdl.so", "dlopen", (void*)my_dlopen, (void**)&orig_dlopen, nullptr);
    bytehook_hook_all("libdl.so", "android_dlopen_ext", (void*)my_android_dlopen_ext, (void**)&orig_android_dlopen_ext, nullptr);
    bytehook_hook_all("libc.so", "fopen", (void*)my_fopen, (void**)&orig_fopen, nullptr);
    bytehook_hook_all("libdl.so", "dlsym", (void*)my_dlsym, (void**)&orig_dlsym, nullptr);
    bytehook_hook_all("libc.so", "ptrace", (void*)my_ptrace, (void**)&orig_ptrace, nullptr);
    bytehook_hook_all("libandroid.so", "AAssetManager_open", (void*)my_AAssetManager_open, (void**)&orig_AAssetManager_open, nullptr);

    // --- 4. Hookuj WebView (jeśli dostępne) ---
    bytehook_hook_all(
        "libwebviewchromium.so",
        "_ZN7android16WebViewFactory4initEP7_JNIEnvP8_jobject",
        (void*)my_WebViewFactory_init,
        (void**)&orig_WebViewFactory_init,
        nullptr
    );
    bytehook_hook_all(
        "libchromium_android_linker.so",
        "_ZN4base14LibraryLoader12loadLibraryEP7_JNIEnvP7_jclassP8_jstring",
        (void*)my_LibraryLoader_loadLibrary,
        (void**)&orig_LibraryLoader_loadLibrary,
        nullptr
    );

    LOGI("[+] Hooki zarejestrowane. Oczekuję na Context...");
    return JNI_VERSION_1_6;
}

// --- HOOK: WebViewFactory.init (placeholder) ---
jobject my_WebViewFactory_init(JNIEnv* env, jobject thiz) {
    LOGI("[+] Hook WebViewFactory.init");
    return orig_WebViewFactory_init ? orig_WebViewFactory_init(env, thiz) : nullptr;
}
