include(FindPackageHandleStandardArgs)

find_path(NCURSES_INCLUDE_DIRS NAMES ncurses.h)
find_library(NCURSES_LIBRARIES NAMES ncurses)

find_package_handle_standard_args(NCURSES
	REQUIRED_VARS NCURSES_INCLUDE_DIRS NCURSES_LIBRARIES)
