find_package(PkgConfig)
pkg_check_modules(PC_CUnit QUIET cunit)

find_path(CUnit_INCLUDE_DIR
  NAMES CUnit/CUnit.h
  PATHS ${PC_CUnit_INCLUDE_DIRS}
)

find_library(CUnit_LIBRARY
  NAMES cunit
  PATHS ${PC_CUnit_LIBRARY_DIRS}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CUnit
  FOUND_VAR CUnit_FOUND
  REQUIRED_VARS
    CUnit_LIBRARY
    CUnit_INCLUDE_DIR
  VERSION_VAR CUnit_VERSION
)

if(CUnit_FOUND)
  set(CUnit_LIBRARIES ${CUnit_LIBRARY})
  set(CUnit_INCLUDE_DIRS ${CUnit_INCLUDE_DIR})
  set(CUnit_DEFINITIONS ${PC_CUnit_CFLAGS_OTHER})
endif()

if(CUnit_FOUND AND NOT TARGET CUnit::CUnit)
  add_library(CUnit::CUnit UNKNOWN IMPORTED)
  set_target_properties(CUnit::CUnit PROPERTIES
    IMPORTED_LOCATION "${CUnit_LIBRARY}"
    INTERFACE_COMPILE_OPTIONS "${PC_CUnit_CFLAGS_OTHER}"
    INTERFACE_INCLUDE_DIRECTORIES "${CUnit_INCLUDE_DIR}"
  )
endif()
