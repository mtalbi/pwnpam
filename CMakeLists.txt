cmake_minimum_required(VERSION 2.8)
include(CheckLibraryExists)

project(hammer C)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake_files)

check_library_exists(c arc4random_buf "stdlib.h" HAS_ARC4RANDOM)
if (NOT HAS_ARC4RANDOM)
	find_package(BSD REQUIRED)
	include_directories(${BSD_INCLUDE_DIRS}/bsd)
	set(LIBS ${LIBS} ${BSD_LIBRARIES})
	# Add _GNU_SOURCE for asprintf
	add_definitions(-DLIBBSD_OVERLAY -D_GNU_SOURCE)
endif()

find_package(NCurses REQUIRED)
set(LIBS ${LIBS} ${NCURSES_LIBRARIES})
include_directories(${NCURSES_INCLUDE_DIRS})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_DEFAULT_SOURCE -D_BSD_SOURCE")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -Werror")

add_executable(cain cain.c)
add_executable(pwnpam pwnpam.c)
target_link_libraries(pwnpam ${LIBS})
