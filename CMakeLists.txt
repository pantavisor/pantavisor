# Set the minimum required version of CMake
cmake_minimum_required(VERSION 3.0)

# Set the project name and version
project(pantavisor VERSION 019)

# subdirectories
add_subdirectory(plugins)

# include cmake packages
include(FindPackageHandleStandardArgs)

# feature flags
set(PANTAVISOR_DM_VERITY OFF CACHE BOOL "Enable support for dm verity mounted squash volumes")
set(PANTAVISOR_DM_CRYPT OFF CACHE BOOL "Enable support for dm crypt mounted disks")
set(PANTAVISOR_PVZRAM_TEST OFF CACHE BOOL "Build pvzram-test binary")
set(PANTAVISOR_DEBUG OFF CACHE BOOL "Enable debug features for Pantavisor")
set(PANTAVISOR_APPENGINE OFF CACHE BOOL "Build Pantavisor as appengine")

# set cmake defintions
set(CODE_INSTALL_BASE "\$ENV{DESTDIR}")

# Find the shared library
find_library(THTTP thttp)
find_library(PICOHTTPPARSER picohttpparser)
find_library(LXC lxc)
find_library(ZLIB z)
find_path(MBEDTLS_INCLUDE_DIRS mbedtls/ssl.h)
find_library(MBEDTLS_LIBRARY mbedtls)
find_library(MBEDX509_LIBRARY mbedx509)
find_library(MBEDCRYPTO_LIBRARY mbedcrypto)
set(MBEDTLS_LIBRARIES "${MBEDTLS_LIBRARY}" "${MBEDX509_LIBRARY}" "${MBEDCRYPTO_LIBRARY}")
find_package_handle_standard_args(MBEDTLS DEFAULT_MSG
    MBEDTLS_INCLUDE_DIRS MBEDTLS_LIBRARY MBEDX509_LIBRARY MBEDCRYPTO_LIBRARY)
mark_as_advanced(MBEDTLS_INCLUDE_DIRS MBEDTLS_LIBRARY MBEDX509_LIBRARY MBEDCRYPTO_LIBRARY)

# Generate version.c
add_custom_command(
    OUTPUT  version.c
    COMMAND sh
	-c
	\"cd ${CMAKE_CURRENT_SOURCE_DIR}\; ./gen_version.sh CMAKE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_SYSTEM_PROCESSOR}\"
)

# Build and Install Pantavisor
add_executable(pantavisor
			addons.c
			addons.h
			apparmor.c
			apparmor.h
			blkid.c
			blkid.h
			bootloader.c
			bootloader.h
			buffer.c
			buffer.h
			cgroup.c
			cgroup.h
			condition.c
			condition.h
			config.c
			config.h
			config_parser.c
			config_parser.h
			ctrl.c
			ctrl.h
			daemons.c
			daemons.h
			debug.c
			debug.h
			disk/disk.c
			disk/disk.h
			disk/disk_crypt.c
			disk/disk_impl.h
			disk/disk_swap.c
			disk/disk_utils.c
			disk/disk_utils.h
			disk/disk_volume.c
			disk/disk_volume.h
			disk/disk_zram.c
			disk/disk_zram_utils.c
			disk/disk_zram_utils.h
			drivers.c
			drivers.h
			group.c
			group.h
			grub.c
			init.c
			init.h
			jsons.c
			jsons.h
			log.c
			log.h
			logger.c
			logger.h
			logserver/logserver.c
			logserver/logserver.h
			logserver/logserver_filetree.c
			logserver/logserver_filetree.h
			logserver/logserver_null.c
			logserver/logserver_null.h
			logserver/logserver_out.c
			logserver/logserver_out.h
			logserver/logserver_singlefile.c
			logserver/logserver_singlefile.h
			logserver/logserver_stdout.c
			logserver/logserver_stdout.h
			logserver/logserver_timestamp.c
			logserver/logserver_timestamp.h
			logserver/logserver_update.c
			logserver/logserver_update.h
			logserver/logserver_utils.c
			logserver/logserver_utils.h
			loop.c
			loop.h
			metadata.c
			metadata.h
			mount.c
			mount.h
			network.c
			network.h
			objects.c
			objects.h
			pantahub.c
			pantahub.h
			pantavisor.c
			pantavisor.h
			parser/parser.c
			parser/parser.h
			parser/parser_bundle.h
			parser/parser_multi1.c
			parser/parser_multi1.h
			parser/parser_system1.c
			parser/parser_system1.h
			paths.c
			paths.h
			ph_logger.c
			ph_logger.h
			platforms.c
			platforms.h
			pvctl_utils.c
			pvctl_utils.h
			pvlogger.c
			pvlogger.h
			rpiab.c
			signature.c
			signature.h
			state.c
			state.h
			storage.c
			storage.h
			trestclient.c
			trestclient.h
			uboot.c
			updater.c
			updater.h
			utils/base64.c
			utils/fs.c
			utils/json.c
			utils/math.c
			utils/pvsignals.c
			utils/pvsignals.h
			utils/pvzlib.c
			utils/pvzlib.h
			utils/socket.c
			utils/socket.h
			utils/str.c
			utils/strrep.c
			utils/system.c
			utils/timer.c
			utils/tsh.c
			version.c version.h
			version.h
			volumes.c
			volumes.h
			wdt.c
			wdt.h
)
target_include_directories(pantavisor PRIVATE ${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/utils ${MBEDTLS_INCLUDE_DIR})
target_link_libraries(pantavisor ${THTTP} ${PICOHTTPPARSER} ${MBEDTLS_LIBRARIES} ${LXC} ${ZLIB})
install(TARGETS pantavisor DESTINATION bin)
IF(PANTAVISOR_DEBUG)
target_compile_definitions(pantavisor PRIVATE PANTAVISOR_DEBUG)
ENDIF()

## install basic filesystem skeleton
install(DIRECTORY skel/ DESTINATION /)

### ... insert defaults/
install(DIRECTORY defaults DESTINATION /etc/pantavisor)

### install PVS secureboot files
IF(DEFINED PANTAVISOR_PVS_DIR)
install(DIRECTORY ${PANTAVISOR_PVS_DIR}/ DESTINATION /etc/pantavisor/pvs/trust FILES_MATCHING PATTERN "*.crt")
ELSE()
install(DIRECTORY pvs/ DESTINATION /etc/pantavisor/pvs)
ENDIF()

### install /init link if not appengine build
if(NOT PANTAVISOR_APPENGINE)
install(CODE "file(CREATE_LINK usr/bin/pantavisor ${CODE_INSTALL_BASE}/init SYMBOLIC)")
ENDIF()

### install scripts
install(FILES scripts/JSON.sh scripts/pv_e2fsgrow scripts/pvcrash
	PERMISSIONS WORLD_READ WORLD_EXECUTE GROUP_READ GROUP_EXECUTE OWNER_READ OWNER_WRITE OWNER_EXECUTE
	DESTINATION /lib/pv/)
install(DIRECTORY scripts/hooks_lxc-mount.d
	FILE_PERMISSIONS WORLD_READ WORLD_EXECUTE GROUP_READ GROUP_EXECUTE OWNER_READ OWNER_WRITE OWNER_EXECUTE
	DESTINATION /lib/pv)
install(PROGRAMS tools/pventer
			tools/fallbear-cmd
	DESTINATION /usr/bin)

### install dm crypt feature
IF(PANTAVISOR_DM_CRYPT)
install(DIRECTORY scripts/volmount/crypt
	FILE_PERMISSIONS WORLD_READ WORLD_EXECUTE GROUP_READ GROUP_EXECUTE OWNER_READ OWNER_WRITE OWNER_EXECUTE
	DESTINATION /lib/pv/volmount)
ENDIF()

### install dm verity feature
IF(PANTAVISOR_DM_VERITY)
install(DIRECTORY scripts/volmount/verity
	FILE_PERMISSIONS WORLD_READ WORLD_EXECUTE GROUP_READ GROUP_EXECUTE OWNER_READ OWNER_WRITE OWNER_EXECUTE
	DESTINATION /lib/pv/volmount)
ENDIF()


# Build and install tests feature
IF(PANTAVISOR_TESTS)
add_executable(test-pv-zram
			disk/disk_zram_utils.c
			disk/disk_zram_utils.h
			utils/pv_zram.c
)
target_link_libraries(test-pv-zram -largp)
install(TARGETS test-pv-zram DESTINATION bin)

add_executable(test-pv-json
			utils/json.test.c
			utils/json.c
			utils/tsh.c utils/tsh.h
			utils/pvsignals.h utils/pvsignals.c
)
target_link_libraries(test-pv-json  ${THTTP})
install(TARGETS test-pv-json DESTINATION bin)

add_executable(test-pv-tsh
			utils/tsh.test.c
			utils/tsh.c utils/tsh.h
			utils/pvsignals.c utils/pvsignals.h
)
target_link_libraries(test-pv-tsh)
install(TARGETS test-pv-tsh DESTINATION bin)
ENDIF()

