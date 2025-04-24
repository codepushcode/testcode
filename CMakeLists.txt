if (POLICY CMP0048)
  cmake_policy(SET CMP0048 NEW)
endif ()

project(cc)
cmake_minimum_required(VERSION 3.11)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-long-long -fPIC -march=native")
set(CMAKE_ENABLE_COMPILE_COMMANDS "ON")

if (${CMAKE_BUILD_TYPE} STREQUAL "Release")
  message("-- Release mode, all optimizations enabled")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -DNDEBUG -Ofast")
endif ()

include_directories(/usr/include/dpu)
add_library(dpu SHARED IMPORTED)
set(DPU_LIB "-ldpu")
set(libs_to_link pthread)

add_executable(cc host/cc.cpp)
target_include_directories(cc PRIVATE include)
target_link_libraries(cc PRIVATE ${libs_to_link} ${DPU_LIB})
