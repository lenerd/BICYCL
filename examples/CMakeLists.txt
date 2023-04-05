add_custom_target (examples COMMAND ${CMAKE_COMMAND} -E sleep 0)

add_executable (chia-vdf chia-vdf.cpp)
target_link_libraries (chia-vdf bicycl)
add_dependencies (examples chia-vdf)
