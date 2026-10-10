#include "main.hpp"

#include "logger.hpp"
#include "constants.hpp"
#include "dex.hpp"
#include "raii.hpp"

#include <jni.h>

#include <string.h> // NOLINT(*-deprecated-headers)
#include <dirent.h>
#include <stdint.h>

void ZygoteLoaderModule::onLoad(zygisk::Api *_api, JNIEnv *_env) {
    api = _api;
    env = _env;

    LOGD("Request dlclose module");
    api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
}

const char *get_package_name(const char *data_dir, const char *process_name) {
    struct stat st; // NOLINT(*-pro-type-member-init)
    // check data dir is accessible for current uid
    if (stat(data_dir, &st) == -1) {
        LOGD("skip injecting into %s - failed to stat data directory", process_name);
        return nullptr;
    }
    const char *last_slash = strrchr(data_dir, '/');
    const char *package_name;
    if (last_slash != nullptr) {
        package_name = last_slash + 1;
        LOGD("Package name: %s for process: %s", package_name, process_name);
    } else {
        LOGD("Failed to parse package name from app_data_dir: %s", data_dir);
        return nullptr;
    }
    return package_name;
}

void ZygoteLoaderModule::preAppSpecialize(zygisk::AppSpecializeArgs *args) {
    RAIIStr process_name = get_string_data(env, args->nice_name);
    RAIIStr data_dir = get_string_data(env, args->app_data_dir);

    if (!process_name || !data_dir) {
        LOGD("skip injecting into %d because its process_name or app_data_dir is null", args->uid);
        return;
    }

    const char *package_name = get_package_name(data_dir, process_name);
    if (!package_name) {
        return;
    }

    RAIIFD module_dir = api->getModuleDir(); // keep alive during preSpecialize
    maybe_install_uid_filter(package_name);   // 按 HMA 名单过滤 uid 可见性（只对配了隐藏的 App 生效）
    tryLoadDex(module_dir, package_name, process_name);
    callJavaPreSpecialize();
}

void ZygoteLoaderModule::postAppSpecialize(const zygisk::AppSpecializeArgs *args) {
    callJavaPostSpecialize();
}

void ZygoteLoaderModule::preServerSpecialize(zygisk::ServerSpecializeArgs *args) {
    RAIIFD module_dir = api->getModuleDir(); // keep alive during preSpecialize
    tryLoadDex(module_dir, PACKAGE_SYSTEM_SERVER, PROCESS_SYSTEM_SERVER);
    callJavaPreSpecialize();
}

void ZygoteLoaderModule::postServerSpecialize(const zygisk::ServerSpecializeArgs *args) {
    callJavaPostSpecialize();
}

bool testPackage(int packages_dir, const char *name) {
    return faccessat(packages_dir, name, F_OK, 0) == 0;
}

bool shouldEnable(int module_dir, const char *package_name) {
    RAIIFD<true> packages_dir = openat(module_dir, "packages", O_PATH | O_DIRECTORY);
    if (!packages_dir.isValid()) return false;
    return testPackage(packages_dir, package_name) ^
           testPackage(packages_dir, ALL_PACKAGES);
}

template<typename F>
jsize open_files(int dirfd, RAIILink<RAIIFile> *files, F filter = [](auto) { return true; }) {
    RAIILink<RAIIFile> *current = files;
    RAIILink<RAIIFile> *prev = nullptr;

    RAIIDir dir(dirfd);
    struct dirent64 *entry;
    jsize count = 0;
    while ((entry = readdir64(dir)) != nullptr) {
        if (entry->d_type == DT_REG && filter(entry->d_name)) {
            if (prev != nullptr) {
                current = new RAIILink<RAIIFile>();
                prev->next = current;
            }

            fatal_assert(current != nullptr); // always true
            current->value = new RAIIFile(dirfd, entry->d_name);

            prev = current;
            current = nullptr;
            count++;
        }
    }
    return count;
}

void ZygoteLoaderModule::tryLoadDex(
        int module_dir, const char *package_name, const char *process_name) {
    if (!shouldEnable(module_dir, package_name)) {
        return;
    }
    // 普通 App 进程只需要 native 的 UID 过滤器，不需要加载模块的 dex/Java 入口
    if (strcmp(package_name, PACKAGE_SYSTEM_SERVER) != 0) {
        return;
    }

    LOGD("Loading in %s", package_name);

    RAIILink<RAIIFile> files;
    jsize count = open_files(module_dir, &files, [](const char *name) {
        return strncmp(name, "classes", 7) == 0 && strstr(name, ".dex") != nullptr;
    });

    entrypoint = (jclass) env->NewGlobalRef(
            dex_load_and_init(
                    env, module_dir,
                    package_name, process_name,
                    &files, count
            )
    );
}

void ZygoteLoaderModule::callJavaPreSpecialize() {
    if (entrypoint != nullptr) {
        call_pre_specialize(env, entrypoint);
    }
}

void ZygoteLoaderModule::callJavaPostSpecialize() {
    if (entrypoint != nullptr) {
        call_post_specialize(env, entrypoint);

        env->DeleteGlobalRef(entrypoint);
        entrypoint = nullptr;
    }
}


// ===== HMA UID 过滤器 =====
extern "C" int uid_filter_init(const uint32_t *uids, int count);

// HMA 配置目录：/data/misc/hide_my_applist_*/uids/<package>.list（每行一个 uid）
// preAppSpecialize 阶段本进程仍是 zygote 域，能读到该目录。
static int read_hma_uid_list(const char *package_name, uint32_t *out, int max) {
    DIR *d = opendir("/data/misc");
    if (d == nullptr) return 0;
    struct dirent *e;
    int count = 0;
    while ((e = readdir(d)) != nullptr) {
        if (strncmp(e->d_name, "hide_my_applist_", 16) != 0) continue;
        char path[512];
        snprintf(path, sizeof(path), "/data/misc/%s/uids/%s.list", e->d_name, package_name);
        FILE *f = fopen(path, "r");
        if (f == nullptr) continue;
        unsigned int v;
        while (count < max && fscanf(f, "%u", &v) == 1) {
            if (v > 0 && v < 1000000u) out[count++] = (uint32_t) v;
        }
        fclose(f);
        if (count > 0) break;
    }
    closedir(d);
    return count;
}

static void maybe_install_uid_filter(const char *package_name) {
    static uint32_t uids[4096];
    int n = read_hma_uid_list(package_name, uids, 4096);
    if (n <= 0) return;                     // 该 App 没配隐藏 → 什么都不做
    int rc = uid_filter_init(uids, n);
    LOGD("UID filter pkg=%s uids=%d install=%d", package_name, n, rc);
}

REGISTER_ZYGISK_MODULE(ZygoteLoaderModule)
