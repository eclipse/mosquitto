FILE(REMOVE_RECURSE
  "libmosquittopp.pdb"
  "libmosquittopp.so"
  "libmosquittopp.so.1.4.90"
  "libmosquittopp.so.1"
)

# Per-language clean rules from dependency scanning.
FOREACH(lang)
  INCLUDE(CMakeFiles/mosquittopp.dir/cmake_clean_${lang}.cmake OPTIONAL)
ENDFOREACH(lang)
