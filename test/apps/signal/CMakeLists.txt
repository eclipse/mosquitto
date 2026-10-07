set(EXCLUDE_LIST " ")
set(PREFIX "apps-")
file(GLOB PY_TEST_FILES signal-*.py)
get_test_files(PY_TEST_FILES "${EXCLUDE_LIST}" PY_TEST_NAMES)

add_python_test(PY_TEST_NAMES ${PREFIX} 0 "signal-args.py")

check_for_missing_tests(PY_TEST_NAMES)
