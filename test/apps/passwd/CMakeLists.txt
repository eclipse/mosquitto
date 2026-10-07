set(EXCLUDE_LIST " ")
set(PREFIX "apps-")
file(GLOB PY_TEST_FILES passwd-*.py)
get_test_files(PY_TEST_FILES "${EXCLUDE_LIST}" PY_TEST_NAMES)

add_python_test(PY_TEST_NAMES ${PREFIX} 0 "passwd-args.py")
add_python_test(PY_TEST_NAMES ${PREFIX} 1 "passwd-changes.py")
add_python_test(PY_TEST_NAMES ${PREFIX} 0 "passwd-stdout.py")

check_for_missing_tests(PY_TEST_NAMES)
