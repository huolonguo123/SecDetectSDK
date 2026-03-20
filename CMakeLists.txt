# ============================================================================
# SecDetect SDK — Android 客户端安全检测(用户态 9 项 + TEE 扩展占位)
#
# 用法(WSL 下,NDK 路径按本机实际改):
#   cmake -S . -B build/arm64 \
#         -DCMAKE_TOOLCHAIN_FILE=/root/strongR/android-ndk-r29/build/cmake/android.toolchain.cmake \
#         -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-23 \
#         -DCMAKE_BUILD_TYPE=Release
#   cmake --build build/arm64 -j
#
# 产物:
#   build/arm64/libsecsdk.so    —— 动态库(给 App/JNI 集成,对外 C ABI)
#   build/arm64/secdetect       —— 命令行 runner(adb push 到 /data/local/tmp 实机验证用)
# ============================================================================
cmake_minimum_required(VERSION 3.22)
project(SecDetectSDK VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# -fvisibility=hidden:库默认隐藏符号,只有显式标注的 C ABI(secdetect_*)
# 才对外可见——防止 C++ 运行时符号污染导出表(本身也是一道"减面"措施,
# 少暴露 = 少给逆向者线索)
add_compile_options(-Wall -Wextra -fvisibility=hidden)

# 所有检测器源码(库与 runner 共用;runner 把库源码再编一份,避免
# 可执行文件还要带 rpath 找 so,adb push 单文件就能跑)
set(SDK_SOURCES
    src/api.cpp
    src/util.cpp
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
    src/tee_stub.cpp
)

# ---- 1) 动态库 libsecsdk.so ----
add_library(secsdk SHARED ${SDK_SOURCES})
target_include_directories(secsdk PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
                                        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
# 动态链接 libc++_shared:否则整个 C++ 运行时会以 DEFAULT 可见性
# 静态链进 .so,导出表被上千个 _ZNKSt... 符号淹没,违背"最小导出面"
target_link_libraries(secsdk PRIVATE c++_shared)
# version script:把 .dynsym 锁死成 export.map 里的 4 个 C 符号,
# 内部实现符号全部 local(见 src/export.map 顶部说明)
target_link_options(secsdk PRIVATE
    -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/src/export.map)
# zlib:重打包检测里 inflate APK 内 deflate 压缩的签名文件需要
find_library(ZLIB_LIB z)
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

# ---- 3) 产物 strip:发布物不带符号表,减小体积、少泄露内部符号名 ----
add_custom_command(TARGET secsdk POST_BUILD
    COMMAND ${CMAKE_STRIP} $<TARGET_FILE:secsdk>)
add_custom_command(TARGET secdetect POST_BUILD
    COMMAND ${CMAKE_STRIP} $<TARGET_FILE:secdetect>)

# ---- 4) 安装规则(可选:make install 时拷到指定目录) ----
install(TARGETS secsdk secdetect
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin)
