# ============================================================================
# SecDetect SDK — Android 客户端安全检测(用户态 12 项 + TEE 扩展占位)
#
# 用法(WSL 下,NDK 路径按本机实际改):
#   cmake -S . -B build/arm64 \
#         -DCMAKE_TOOLCHAIN_FILE=/root/strongR/android-ndk-r29/build/cmake/android.toolchain.cmake \
#         -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-23 \
#         -DCMAKE_BUILD_TYPE=Release
#   cmake --build build/arm64 -j
#
# 产物:
#   build/arm64/libsecsdk.so      —— 纯 native 动态库(C ABI,给 NDK/JNI 集成)
#   build/arm64/libsecsdk-jni.so  —— JNI 版(Android 下默认编,入口 JNI_OnLoad)
#   build/arm64/secdetect         —— 命令行 runner(adb push 到 /data/local/tmp)
#
# 关掉 JNI 版:-DSEC_BUILD_JNI=OFF
# ============================================================================
cmake_minimum_required(VERSION 3.22)
project(SecDetectSDK VERSION 1.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

option(SEC_BUILD_JNI "Build the JNI bridge (libsecsdk-jni.so, Android only)" ON)

# -fvisibility=hidden:库默认隐藏符号,只有显式标注的 C ABI(secdetect_*)
# 才对外可见——防止 C++ 运行时符号污染导出表(本身也是一道"减面"措施,
# 少暴露 = 少给逆向者线索)
add_compile_options(-Wall -Wextra -fvisibility=hidden)

# 所有检测器源码(库 / runner / JNI 版共用)
set(SDK_SOURCES
    src/api.cpp
    src/util.cpp
    src/apk_signature.cpp
    src/env_facts.cpp
    src/det_root.cpp
    src/det_debugger.cpp
    src/det_frida.cpp
    src/det_xposed.cpp
    src/det_emulator.cpp
    src/det_vm.cpp
    src/det_repack.cpp
    src/det_bootloader.cpp
    src/det_usb.cpp
    src/det_module.cpp
    src/det_integrity.cpp
    src/det_ida.cpp
    src/tee_stub.cpp
)

# zlib:重打包检测里 inflate APK 内 deflate 压缩的 v1 签名文件需要
find_library(ZLIB_LIB z)

# ---- 1) 动态库 libsecsdk.so(纯 native 集成用) ----
add_library(secsdk SHARED ${SDK_SOURCES})
target_include_directories(secsdk PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
                                        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
# 动态链接 libc++_shared:否则整个 C++ 运行时会以 DEFAULT 可见性
# 静态链进 .so,导出表被上千个 _ZNKSt... 符号淹没,违背"最小导出面"
target_link_libraries(secsdk PRIVATE c++_shared)
# version script:把 .dynsym 锁死成 export.map 里的 C 符号,
# 内部实现符号全部 local(见 src/export.map 顶部说明)
target_link_options(secsdk PRIVATE
    -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/src/export.map)
if(ZLIB_LIB)
    target_link_libraries(secsdk PRIVATE ${ZLIB_LIB})
    target_compile_definitions(secsdk PRIVATE HAVE_ZLIB=1)
endif()

# ---- 2) 命令行 runner secdetect ----
add_executable(secdetect demo/main.cpp ${SDK_SOURCES})
target_include_directories(secdetect PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
                                            ${CMAKE_CURRENT_SOURCE_DIR}/src)
if(ZLIB_LIB)
    target_link_libraries(secdetect PRIVATE ${ZLIB_LIB})
    target_compile_definitions(secdetect PRIVATE HAVE_ZLIB=1)
endif()

# ---- 3) JNI 桥 libsecsdk-jni.so(只编逻辑,不含任何 Android 依赖之外的库) ----
if(ANDROID AND SEC_BUILD_JNI)
    add_library(secsdk-jni SHARED jni/sec_jni.cpp ${SDK_SOURCES})
    target_include_directories(secsdk-jni PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
                                                  ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(secsdk-jni PRIVATE c++_shared log)
    # JNI 入口必须导出:用单独的 version script(只放开 JNI_OnLoad + C ABI)
    target_link_options(secsdk-jni PRIVATE
        -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/jni/export_jni.map)
    if(ZLIB_LIB)
        target_link_libraries(secsdk-jni PRIVATE ${ZLIB_LIB})
        target_compile_definitions(secsdk-jni PRIVATE HAVE_ZLIB=1)
    endif()
    add_custom_command(TARGET secsdk-jni POST_BUILD
        COMMAND ${CMAKE_STRIP} $<TARGET_FILE:secsdk-jni>)
    install(TARGETS secsdk-jni LIBRARY DESTINATION lib)
endif()

# ---- 4) 产物 strip:发布物不带符号表,减小体积、少泄露内部符号名 ----
add_custom_command(TARGET secsdk POST_BUILD
    COMMAND ${CMAKE_STRIP} $<TARGET_FILE:secsdk>)
add_custom_command(TARGET secdetect POST_BUILD
    COMMAND ${CMAKE_STRIP} $<TARGET_FILE:secdetect>)

# ---- 5) 安装规则(可选:make install 时拷到指定目录) ----
install(TARGETS secsdk secdetect
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin)

# ---- 6) Java 辅助类不参与 CMake 构建,直接拷进你的 Android 工程:
#         java/com/sec/detect/*.java   (包名 com.sec.detect,与 jni/sec_jni.cpp 一致)
