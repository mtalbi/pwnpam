include(FindPackageHandleStandardArgs)

find_path(BSD_INCLUDE_DIRS NAMES bsd/bsd.h)
find_library(BSD_LIBRARIES NAMES bsd)

find_package_handle_standard_args(BSD
	REQUIRED_VARS BSD_INCLUDE_DIRS BSD_LIBRARIES)
