# Set the minimum required version of CMake
cmake_minimum_required(VERSION 3.0)

# Set the project name and version
project(pantavisor VERSION 019)

# Find the shared library
find_library(THTTP thttp)
find_library(PICOHTTPPARSER picohttpparser)
find_library(LXC lxc)

add_subdirectory(plugins)

include(FindPackageHandleStandardArgs)

find_path(MBEDTLS_INCLUDE_DIRS mbedtls/ssl.h)
find_library(MBEDTLS_LIBRARY mbedtls)
find_library(MBEDX509_LIBRARY mbedx509)
find_library(MBEDCRYPTO_LIBRARY mbedcrypto)
set(MBEDTLS_LIBRARIES "${MBEDTLS_LIBRARY}" "${MBEDX509_LIBRARY}" "${MBEDCRYPTO_LIBRARY}")
find_package_handle_standard_args(MBEDTLS DEFAULT_MSG
    MBEDTLS_INCLUDE_DIRS MBEDTLS_LIBRARY MBEDX509_LIBRARY MBEDCRYPTO_LIBRARY)
mark_as_advanced(MBEDTLS_INCLUDE_DIRS MBEDTLS_LIBRARY MBEDX509_LIBRARY MBEDCRYPTO_LIBRARY)

# Set the source files for the binary
set(SOURCES  debug.c
			init.c
			cgroup.c
			loop.c
			logger.c
			log.c
			logserver/logserver_utils.c
			logserver/logserver_out.c
			logserver/logserver_singlefile.c
			logserver/logserver_filetree.c
			logserver/logserver_null.c
			logserver/logserver.c
			config_parser.c
			config.c
			pantavisor.c
			state.c
			group.c
			condition.c
			platforms.c
			addons.c
			volumes.c
			signature.c
			parser/parser.c
			parser/parser_multi1.c
			parser/parser_system1.c
			objects.c
			utils/tsh.c
			utils/system.c
			utils/str.c
			utils/strrep.c
			utils/json.c
			utils/base64.c
			utils/math.c
			utils/timer.c
			utils/fs.c
			jsons.c
			pantahub.c
			updater.c
			bootloader.c
			trestclient.c
			uboot.c
			grub.c
			storage.c
			metadata.c
			ctrl.c
			wdt.c
			network.c
			pvlogger.c
			pvctl_utils.c
			mount.c
			ph_logger.c
			buffer.c
			blkid.c
			paths.c
			drivers.c
			addons.h
			buffer.h
			config_parser.h
			drivers.h
			jsons.h
			logserver/logserver_utils.h
			logserver/logserver_out.h
			logserver/logserver_singlefile.h
			logserver/logserver_null.h
			logserver/logserver.h
			logserver/logserver_filetree.h
			mount.h
			pantahub.h
			ph_logger.h
			pvlogger.h
			storage.h
			version.h
			blkid.h
			condition.h
			ctrl.h
			cgroup.h
			group.h
			logger.h
			loop.h
			network.h
			pantavisor.h
			platforms.h
			signature.h
			trestclient.h
			volumes.h
			bootloader.h
			config.h
			debug.h
			init.h
			log.h
			metadata.h
			objects.h
			paths.h
			pvctl_utils.h
			state.h
			updater.h
			wdt.h
			version.c version.h
			parser/parser_bundle.h
			parser/parser.h
			parser/parser_multi1.h
			parser/parser_system1.h
)

add_compile_definitions(PANTAVISOR_DEBUG=yes)

add_custom_command(
    OUTPUT  version.c
    COMMAND sh
	-c
	\"cd ${CMAKE_CURRENT_SOURCE_DIR}\; ./gen_version.sh CMAKE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_SYSTEM_PROCESSOR}\"
)

include_directories(${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/utils ${MBEDTLS_INCLUDE_DIR})

# Create the executable and link against the shared library
add_executable(pantavisor ${SOURCES})

target_link_libraries(pantavisor ${THTTP} ${PICOHTTPPARSER} ${MBEDTLS_LIBRARIES} ${LXC})

# install skel/ directory
install(DIRECTORY skel/ DESTINATION /)

# install pantavisor cmake target binary
install(TARGETS pantavisor DESTINATION bin)

# put defaults/ in place
install(DIRECTORY defaults DESTINATION /etc/pantavisor)

IF(DEFINED PANTAVISOR_PVS_DIR)
install(DIRECTORY ${PANTAVISOR_PVS_DIR}/ DESTINATION /etc/pantavisor/pvs/trust FILES_MATCHING PATTERN "*.crt")
ELSE()
install(DIRECTORY pvs/ DESTINATION /etc/pantavisor/pvs)
ENDIF()


install(PROGRAMS tools/pventer
		tools/fallbear-cmd
	DESTINATION /usr/bin)

