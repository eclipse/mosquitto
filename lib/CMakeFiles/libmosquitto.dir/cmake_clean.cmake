FILE(REMOVE_RECURSE
  "libmosquitto.pdb"
  "libmosquitto.so"
  "libmosquitto.so.1.4.90"
  "libmosquitto.so.1"
)

# Per-language clean rules from dependency scanning.
FOREACH(lang)
  INCLUDE(CMakeFiles/libmosquitto.dir/cmake_clean_${lang}.cmake OPTIONAL)
ENDFOREACH(lang)
