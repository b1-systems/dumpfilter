cmake_minimum_required(VERSION 2.6)
project(dumpfilter C)

SET(INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})

SET(CONFIG_PREFIX "/etc" CACHE STRING
      "Config prefix"
      FORCE)

add_subdirectory(src)
add_subdirectory(test)


SET_PROPERTY(GLOBAL APPEND PROPERTY CMAKE_C_FLAGS "-Wall")

