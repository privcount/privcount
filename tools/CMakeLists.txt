## privexctl: tool for dumping privex stats from Tor and loading into the privex DC from file later
## build: "cmake . && make"
project(privexctl)
cmake_minimum_required(VERSION 2.8.8 FATAL_ERROR)

add_definitions(-D_GNU_SOURCE)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -fno-inline -fno-strict-aliasing -U_FORTIFY_SOURCE")

## the main privexctl dynamic executable, can run both inside AND outside of shadow
## this only works if none of our internal symbols need to be interposed!
add_executable(privexctl privexctl.c)
set_target_properties(privexctl PROPERTIES 
        INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/lib 
        INSTALL_RPATH_USE_LINK_PATH TRUE 
        LINK_FLAGS "-pie -rdynamic -Wl,--no-as-needed")
install(TARGETS privexctl DESTINATION bin)
