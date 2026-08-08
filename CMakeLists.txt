cmake_minimum_required(VERSION 3.26)

project(x64dbgMCPBuild NONE)

if(NOT CMAKE_GENERATOR MATCHES "^Visual Studio")
    message(FATAL_ERROR
        "x64dbgMCP requires a Visual Studio generator. "
        "Configure with -A Win32 for x86 or -A x64 for x64.")
endif()

if(CMAKE_VS_PLATFORM_NAME STREQUAL "Win32")
    set(X64DBG_MSBUILD_PLATFORM "Win32")
    set(X64DBG_OUTPUT_PLATFORM "win32")
    set(X64DBG_RELEASE_ARCH "x32")
elseif(CMAKE_VS_PLATFORM_NAME STREQUAL "x64")
    set(X64DBG_MSBUILD_PLATFORM "x64")
    set(X64DBG_OUTPUT_PLATFORM "x64")
    set(X64DBG_RELEASE_ARCH "x64")
else()
    message(FATAL_ERROR
        "Unsupported Visual Studio platform '${CMAKE_VS_PLATFORM_NAME}'. "
        "Configure with -A Win32 for x86 or -A x64 for x64.")
endif()

if(NOT CMAKE_VS_MSBUILD_COMMAND)
    message(FATAL_ERROR "CMake did not resolve MSBuild for the selected Visual Studio generator.")
endif()

set(X64DBG_RELEASE_ROOT
    "$ENV{USERPROFILE}/Downloads/Tools/x64dbg/release"
    CACHE PATH
    "Root of the unpacked x64dbg release tree")

set(X64DBGMCP_PROJECT "${CMAKE_SOURCE_DIR}/x64dbgMCP/x64dbgMCP.vcxproj")
set(X64DBGMCP_OUTPUT_DIR
    "${CMAKE_SOURCE_DIR}/out/bin/${X64DBG_OUTPUT_PLATFORM}-$<CONFIG>")
set(X64DBGMCP_PLUGIN_DIR
    "${X64DBG_RELEASE_ROOT}/${X64DBG_RELEASE_ARCH}/plugins")

# Keep the existing vcxproj as the authoritative C++/CLI build definition.
add_custom_target(build_x64dbg_plugin ALL
    COMMAND "${CMAKE_VS_MSBUILD_COMMAND}"
        "${X64DBGMCP_PROJECT}"
        /restore
        /target:Build
        /property:Configuration=$<CONFIG>
        /property:Platform=${X64DBG_MSBUILD_PLATFORM}
        /property:SolutionDir=${CMAKE_SOURCE_DIR}/
        /property:CopyLocalLockFileAssemblies=true
        /property:RestoreIgnoreFailedSources=true
        /maxCpuCount
    COMMENT
        "Building x64dbgMCP ($<CONFIG>|${X64DBG_MSBUILD_PLATFORM}) with MSBuild"
    USES_TERMINAL
    VERBATIM)

# Explicit deployment task: copy the complete MSBuild OutputPath into x64dbg.
add_custom_target(deploy_x64dbg_plugin
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${X64DBGMCP_PLUGIN_DIR}"
    COMMAND "${CMAKE_COMMAND}" -E copy_directory_if_different
        "${X64DBGMCP_OUTPUT_DIR}"
        "${X64DBGMCP_PLUGIN_DIR}"
    DEPENDS build_x64dbg_plugin
    COMMENT
        "Deploying ${X64DBGMCP_OUTPUT_DIR} to ${X64DBGMCP_PLUGIN_DIR}"
    USES_TERMINAL
    VERBATIM)
