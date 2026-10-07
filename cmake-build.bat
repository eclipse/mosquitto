set BUILD_TYPE=RelWithDebInfo
set BUILD_ROOT=%CD%

cmake -B build -DCMAKE_BUILD_TYPE=%BUILD_TYPE% -DCMAKE_GENERATOR_PLATFORM=x64 -DCMAKE_TOOLCHAIN_FILE=..\vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows-release -DVCPKG_MANIFEST_MODE=ON
cmake --build build --config %BUILD_TYPE% -j16
