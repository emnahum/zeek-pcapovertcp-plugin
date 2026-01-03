
cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(ZeekPluginPcapOverTcp)

include(ZeekPlugin)

zeek_plugin_begin(Zeek PcapOverTcp)
zeek_plugin_cc(src/Plugin.cc)
zeek_plugin_cc(src/PcapOverTcp.cc)
zeek_plugin_bif(src/pcapovertcp.bif)
zeek_plugin_dist_files(zeekctl/pcapovetcp.py README COPYING VERSION)
zeek_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
