# auto generated


include( "@CMAKE_BINARY_DIR@/mosquitto-targets.cmake" )


set( MOSQUITTO_INCLUDE_DIRS 
  "@CMAKE_SOURCE_DIR@/lib"
  "@CMAKE_SOURCE_DIR@/lib/cpp"
)

set( MOSQUITTO_LIBRARIES 
  general libmosquitto 
  general mosquittopp )

set( MOSQUITTO_FOUND TRUE )
