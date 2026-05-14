cmake_minimum_required(VERSION 3.20)
project(argus C CXX)
include_directories(include)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find dependencies (via vcpkg)
find_package(cJSON CONFIG REQUIRED)
# find_package(unofficial-yara CONFIG REQUIRED)
# Uncomment above when YARA is installed via vcpkg

# Shared include path (events.h visible to both targets)
find_path(DETOURS_INCLUDE_DIRS "detours/detours.h")
find_library(DETOURS_LIBRARY detours REQUIRED)
include_directories(${DETOURS_INCLUDE_DIRS} ${DETOURS_INCLUDE_DIRS}/detours)

# ============================================================================
# argus_hook - Shared Library (DLL)
# ============================================================================
add_library(argus_hook SHARED
    src/hook_dll/dllmain.cpp
    src/hook_dll/hooks.c
    src/hook_dll/hooks.h
    src/hook_dll/event_queue.c
    src/hook_dll/event_queue.h
    src/hook_dll/ipc_client.c
    src/hook_dll/ipc_client.h
)

target_include_directories(argus_hook PRIVATE
    ${CMAKE_SOURCE_DIR}/src/hook_dll
)

# Link libraries for hook DLL
target_link_libraries(argus_hook PRIVATE cjson)

# Link Detours - check for vcpkg or local lib
if(EXISTS "${CMAKE_SOURCE_DIR}/Malware/HookChallengeSolution/detoursx64.lib")
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_link_libraries(argus_hook PRIVATE
            ${CMAKE_SOURCE_DIR}/Malware/HookChallengeSolution/detoursx64.lib
        )
    else()
        target_link_libraries(argus_hook PRIVATE
            ${CMAKE_SOURCE_DIR}/Malware/HookChallengeSolution/detoursx86.lib
        )
    endif()
else()
    # Try to find Detours via vcpkg
    # find_package(Detours CONFIG REQUIRED)
    # Find Detours headers and library (vcpkg style)
    find_path(DETOURS_INCLUDE_DIRS "detours/detours.h")
    find_library(DETOURS_LIBRARY detours REQUIRED)
    include_directories(${DETOURS_INCLUDE_DIRS})
    target_link_libraries(argus_hook PRIVATE cjson ${DETOURS_LIBRARY})
endif()

# ============================================================================
# argus_agent - Executable
# ============================================================================
add_executable(argus_agent
    src/agent/main.c
    src/agent/ipc_server.c
    src/agent/ipc_server.h
    src/agent/scanner.c
    src/agent/scanner.h
    src/agent/yara_scanner.c
    src/agent/yara_scanner.h
    src/agent/pesieve_scanner.cpp
    src/agent/pesieve_scanner.h
    src/hook_dll/event_queue.c
    src/hook_dll/event_queue.h
    src/hook_dll/ipc_client.c
    src/hook_dll/ipc_client.h
)

target_include_directories(argus_agent PRIVATE
    ${CMAKE_SOURCE_DIR}/src/agent
    ${CMAKE_SOURCE_DIR}/src/hook_dll
)

# Link libraries for agent
target_link_libraries(argus_agent PRIVATE
    cjson
    ws2_32
    winhttp
)

# Optional: Add YARA support if available
# Uncomment when YARA is installed via vcpkg
# if(TARGET unofficial::yara)
#     target_compile_definitions(argus_agent PRIVATE YARA_AVAILABLE)
#     target_link_libraries(argus_agent PRIVATE unofficial::yara)
# endif()

# Set output directories
set_target_properties(argus_hook argus_agent PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)

# Installation rules
install(TARGETS argus_hook argus_agent
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(DIRECTORY include/argus
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)
