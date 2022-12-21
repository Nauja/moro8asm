cmake_minimum_required(VERSION 3.3)
 
# Specify search path for CMake modules to be loaded by include() 
# and find_package()
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules")

include(ExternalProject)

set(MORO8ASM_VERSION_MAJOR 0)
set(MORO8ASM_VERSION_MINOR 0)
set(MORO8ASM_VERSION_PATCH 1)
set(MORO8ASM_VERSION "${MORO8ASM_VERSION_MAJOR}.${MORO8ASM_VERSION_MINOR}.${MORO8ASM_VERSION_PATCH}")

#find_package(Git)
if(Git_FOUND) 
    execute_process(
        COMMAND ${GIT_EXECUTABLE} status
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        ERROR_VARIABLE RESULT_STRING
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    string(LENGTH "${RESULT_STRING}" LENGTH_RESULT_STRING)

    if(${LENGTH_RESULT_STRING} EQUAL 0)

        execute_process(
            COMMAND ${GIT_EXECUTABLE} log -1 --format=%H
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_VARIABLE GIT_COMMIT_HASH
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )

        string(SUBSTRING ${GIT_COMMIT_HASH} 0 7 GIT_COMMIT_HASH)
        set(VERSION_HASH ${GIT_COMMIT_HASH} )

        execute_process(
            COMMAND ${GIT_EXECUTABLE} rev-list HEAD --count
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_VARIABLE VERSION_REVISION
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )

    endif()
endif()

project(moro8asm VERSION ${MORO8ASM_VERSION} LANGUAGES C)

include(ConfigureChecks)

option(MORO8ASM_STATIC "Build a static library" ON)
option(MORO8ASM_UNIT_TESTING "Unit Tests Enabled" ON)
option(MORO8ASM_DOXYGEN "Docs Enabled" OFF)
option(MORO8ASM_WITH_CLI "Build the command-line interface" ON)

# disallow in-source build
include(MacroEnsureOutOfSourceBuild)
macro_ensure_out_of_source_build("${PROJECT_NAME} requires an out of source build. Please create a separate build directory and run 'cmake /path/to/${PROJECT_NAME} [options]' there.")

message("Building for target : ${CMAKE_SYSTEM_NAME}")
message("PROJECT_VERSION: ${MORO8ASM_VERSION}")
message("VERSION_HASH: ${VERSION_HASH}")
configure_file(moro8asm.h.cmake ${CMAKE_CURRENT_SOURCE_DIR}/moro8asm.h)

# moro8
set(MORO8_SOURCE_DIR "${CMAKE_SOURCE_DIR}/vendor/moro8")
set(MORO8_INCLUDE_DIR "${MORO8_SOURCE_DIR}")
set(MORO8_BINARY_DIR "${MORO8_SOURCE_DIR}/build")

ExternalProject_Add(moro8
  PREFIX moro8
  SOURCE_DIR ${MORO8_SOURCE_DIR}
  BINARY_DIR ${MORO8_BINARY_DIR}
  INSTALL_COMMAND ""
  CMAKE_ARGS
        -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
        -DMORO8_STATIC=On
        -DMORO8_MINIMALIST=On
        -DMORO8_UNIT_TESTING=Off
        -DMORO8_DOXYGEN=Off
)

add_library(moro8_vendor STATIC SHARED IMPORTED)

if(MSVC)
  set(MORO8_LIBRARY "${MORO8_BINARY_DIR}/${CMAKE_CFG_INTDIR}/moro8.lib")
else()
  set(MORO8_LIBRARY "${MORO8_BINARY_DIR}/moro8.a")
endif()

add_dependencies(moro8_vendor moro8)

# moro8asm
set(MORO8ASM_LIB moro8asm)

file(GLOB HEADERS moro8asm.h)
set(SOURCES moro8asm.c)

add_library("${MORO8ASM_LIB}" SHARED "${HEADERS}" "${SOURCES}")
target_compile_options("${MORO8ASM_LIB}"
                        PRIVATE
                            ${DEFAULT_C_COMPILE_FLAGS}
                            -DHAVE_CONFIG_H)
                               
target_include_directories(${MORO8ASM_LIB}
                            PRIVATE
                                ${CMAKE_CURRENT_BINARY_DIR}
                                ${MORO8_INCLUDE_DIR}
                            PUBLIC
                                ${CMAKE_CURRENT_SOURCE_DIR})
if (MORO8ASM_STATIC)
    
    set(MORO8ASM_STATIC_LIB "${MORO8ASM_LIB}-static")

    add_library(${MORO8ASM_STATIC_LIB} STATIC "${HEADERS}" "${SOURCES}")
    set_target_properties(${MORO8ASM_STATIC_LIB} PROPERTIES OUTPUT_NAME "${MORO8ASM_LIB}")
    set_target_properties(${MORO8ASM_STATIC_LIB} PROPERTIES PREFIX "")

    target_compile_options(${MORO8ASM_STATIC_LIB}
                           PRIVATE
                               ${DEFAULT_C_COMPILE_FLAGS}
                               -DHAVE_CONFIG_H
                               -DMORO8ASM_HIDE_SYMBOLS)
                               
    target_include_directories(${MORO8ASM_STATIC_LIB}
                               PRIVATE
                                   ${CMAKE_CURRENT_BINARY_DIR}
                                   ${MORO8_INCLUDE_DIR}
                               PUBLIC
                                    ${CMAKE_CURRENT_SOURCE_DIR})
endif()

if (MORO8ASM_WITH_CLI OR MORO8ASM_UNIT_TESTING)
# libfs
set(LIBFS_SOURCE_DIR "${CMAKE_SOURCE_DIR}/vendor/libfs")
set(LIBFS_INCLUDE_DIR "${LIBFS_SOURCE_DIR}")
set(LIBFS_BINARY_DIR "${LIBFS_SOURCE_DIR}/build")

ExternalProject_Add(libfs
  PREFIX libfs
  SOURCE_DIR ${LIBFS_SOURCE_DIR}
  BINARY_DIR ${LIBFS_BINARY_DIR}
  INSTALL_COMMAND ""
  CMAKE_ARGS
        -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
        -DLIBFS_STATIC=On
        -DLIBFS_UNIT_TESTING=Off
        -DLIBFS_DOXYGEN=Off
)

add_library(libfs_vendor STATIC SHARED IMPORTED)

if(MSVC)
  set(LIBFS_LIBRARY "${LIBFS_BINARY_DIR}/${CMAKE_CFG_INTDIR}/libfs.lib")
else()
  set(LIBFS_LIBRARY "${LIBFS_BINARY_DIR}/libfs.a")
endif()

add_dependencies(libfs_vendor libfs)

message("LIBFS_BINARY_DIR=${LIBFS_BINARY_DIR}")
message("LIBFS_LIBRARY=${LIBFS_LIBRARY}")
endif(MORO8ASM_WITH_CLI OR MORO8ASM_UNIT_TESTING)

if (MORO8ASM_WITH_CLI)
    
    set(MORO8ASM_CLI "moro8asm-cli")

    add_executable(${MORO8ASM_CLI} "cli.c")
            
    target_compile_options(${MORO8ASM_CLI}
                           PRIVATE
                               ${DEFAULT_C_COMPILE_FLAGS}
                               -DLIBFS_STATIC=On
                               -DMORO8_STATIC=On)

    target_link_libraries(${MORO8ASM_CLI} PRIVATE ${LIBFS_LIBRARY} ${MORO8_LIBRARY} ${MORO8_ASM_STATIC_LIB})

    target_include_directories(${MORO8ASM_CLI}
        PRIVATE 
            ${LIBFS_INCLUDE_DIR}
            ${LIBFS_BINARY_DIR}
            ${MORO8_INCLUDE_DIR}
            ${MORO8_BINARY_DIR})

    # Link libfs and moro8
    add_dependencies(${MORO8ASM_CLI} libfs moro8)

    set_target_properties(${MORO8ASM_CLI} PROPERTIES RUNTIME_OUTPUT_NAME moro8asm)

endif(MORO8ASM_WITH_CLI)

# include cmocka
if (MORO8ASM_UNIT_TESTING)
    if (NOT MORO8ASM_STATIC)
        message("Skip unit testing because MORO8ASM_STATIC option is off")

    else()
        include(AddCMockaTest)
        add_subdirectory(tests)

    endif(NOT MORO8ASM_STATIC)
endif (MORO8ASM_UNIT_TESTING)

if (MORO8ASM_DOXYGEN)
    add_subdirectory (docs)
endif (MORO8ASM_DOXYGEN)