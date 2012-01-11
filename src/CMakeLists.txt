cmake_minimum_required(VERSION 2.8)

install(FILES dumpfilter.ini
        DESTINATION ${CONFIG_PREFIX}/dumpfilter)
install(FILES dumpfilter.gdb
        DESTINATION ${CONFIG_PREFIX}/dumpfilter)
install(PROGRAMS dumpfilter.init
        RENAME dumpfilter
        DESTINATION ${CONFIG_PREFIX}/init.d)
install(PROGRAMS dumpfilter.py
        RENAME dumpfilter
        DESTINATION sbin)
