# Set the minimum required version of CMake
cmake_minimum_required(VERSION 3.0)

# Set the project name and version
project(pantavisor VERSION 019)

# include cmake packages
include(FindPackageHandleStandardArgs)

# feature flags
set(PANTAVISOR_DM_VERITY OFF CACHE BOOL "Enable support for dm verity mounted squash volumes")
set(PANTAVISOR_DM_CRYPT OFF CACHE BOOL "Enable support for dm crypt mounted disks")
set(PANTAVISOR_PVZRAM_TEST OFF CACHE BOOL "Build pvzram-test binary")
set(PANTAVISOR_DEBUG OFF CACHE BOOL "Enable debug features for Pantavisor")
set(PANTAVISOR_APPENGINE OFF CACHE BOOL "Build Pantavisor as appengine")
set(PANTAVISOR_DEFAULTS_SKIP_INSTALL OFF CACHE BOOL "Skip installing defaults/ to etc/pantavisor")
set(PANTAVISOR_PVS_SKIP_INSTALL OFF CACHE BOOL "Skip installing developer trust store")
set(PANTAVISOR_DISTRO_VERSION "" CACHE STRING "Set a distro version to include in pantavisor build version")
set(PANTAVISOR_DISTRO_NAME "" CACHE STRING "Set a distro name to include in pantavisor build version")
set(PANTAVISOR_E2FSGROW_ENABLE ON CACHE BOOL "Enable autogrow partition feature")
set(PANTAVISOR_RUNTIME ON CACHE BOOL "build pantavisor runtime itself")
set(PANTAVISOR_PVTX ON CACHE BOOL "build pantavisor pvtx")
set(PANTAVISOR_PVTX_STATIC OFF CACHE BOOL "build pantavisor pvtx static")
set(PANTAVISOR_CLANG_FORMAT_CHECK OFF CACHE BOOL "run clang-format check on build")

# set cmake defintions
set(CODE_INSTALL_BASE "\$ENV{DESTDIR}")

if(PANTAVISOR_CLANG_FORMAT_CHECK)

# Find all .c and .h files
file(GLOB_RECURSE ALL_SOURCE_FILES
    ${CMAKE_SOURCE_DIR}/*.c
    ${CMAKE_SOURCE_DIR}/*.h
)

# Exclude build directory
list(FILTER ALL_SOURCE_FILES EXCLUDE REGEX "${CMAKE_BINARY_DIR}/.*")

# Find clang-format
find_program(CLANG_FORMAT NAMES clang-format)

if(CLANG_FORMAT)
    add_custom_target(
        format-check ALL  # ALL makes it run on every build
        COMMAND ${CLANG_FORMAT}
        --dry-run
        --Werror
        --style=file
        ${ALL_SOURCE_FILES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Checking code formatting with clang-format (build will fail if formatting is incorrect)"
    )
else()
    message(FATAL_ERROR "clang-format not found! Please install clang-format to build this project.")
endif()

endif() #PANTAVISOR_CLANG_FORMAT_CHECK

# Pantavisor Runtime

IF (PANTAVISOR_RUNTIME)

# subdirectories
add_subdirectory(plugins)

### Pantavisor links shared where possible
set(CMAKE_FIND_LIBRARY_SUFFIXES ".so;.a")

# Find the shared library
find_library(PANTAVISOR_RUNTIME_THTTP thttp)
find_library(PANTAVISOR_RUNTIME_ZLIB z)
find_path(PANTAVISOR_RUNTIME_MBEDTLS_INCLUDE_DIRS mbedtls/ssl.h)
find_library(PANTAVISOR_RUNTIME_MBEDTLS_LIBRARY mbedtls)
find_library(PANTAVISOR_RUNTIME_MBEDX509_LIBRARY mbedx509)
find_library(PANTAVISOR_RUNTIME_MBEDCRYPTO_LIBRARY mbedcrypto)
find_library(PANTAVISOR_RUNTIME_PICOHTTPPARSER picohttpparser)
find_library(PANTAVISOR_RUNTIME_LXC lxc)
find_library(PANTAVISOR_RUNTIME_EVENT event)
find_library(PANTAVISOR_RUNTIME_EVENT_MBEDTLS event_mbedtls)


set(PANTAVISOR_RUNTIME_MBEDTLS_LIBRARIES
	${PANTAVISOR_RUNTIME_MBEDTLS_LIBRARY}
	${PANTAVISOR_RUNTIME_MBEDX509_LIBRARY}
	${PANTAVISOR_RUNTIME_MBEDCRYPTO_LIBRARY}
)
find_package_handle_standard_args(
	PANTAVISOR_RUNTIME_MBEDTLS
	DEFAULT_MSG
	PANTAVISOR_RUNTIME_MBEDTLS_INCLUDE_DIRS
	PANTAVISOR_RUNTIME_MBEDTLS_LIBRARY
	PANTAVISOR_RUNTIME_MBEDX509_LIBRAR
	PANTAVISOR_RUNTIME_MBEDCRYPTO_LIBRARY
)

mark_as_advanced(PANTAVISOR_RUNTIME_MBEDTLS_INCLUDE_DIRS
	PANTAVISOR_RUNTIME_MBEDTLS_LIBRARY
	PANTAVISOR_RUNTIME_MBEDX509_LIBRARY
	PANTAVISOR_RUNTIME_MBEDCRYPTO_LIBRARY
)

set(PANTAVISOR_RUNTIME_EVENT_LIBRARIES
	${PANTAVISOR_RUNTIME_EVENT}
	${PANTAVISOR_RUNTIME_EVENT_MBEDTLS}
)

#### Compiler options
add_compile_options(-Werror)

### Generate version.c
add_custom_command(
    OUTPUT  version.c
    COMMAND sh
	-c
	\"cd ${CMAKE_CURRENT_SOURCE_DIR}\; DISTRO_NAME=${PANTAVISOR_DISTRO_NAME} DISTRO_VERSION=${PANTAVISOR_DISTRO_VERSION} ./gen_version.sh CMAKE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_SYSTEM_PROCESSOR}\"
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
			ctrl/ctrl.c
			ctrl/ctrl.h
			ctrl/ctrl_buildinfo_ep.c
			ctrl/ctrl_devmeta_ep.c
			ctrl/ctrl_download.c
			ctrl/ctrl_download.h
			ctrl/ctrl_drivers_ep.c
			ctrl/ctrl_callback.c
			ctrl/ctrl_callback.h
			ctrl/ctrl_caller.c
			ctrl/ctrl_caller.h
			ctrl/ctrl_containers_ep.c
			ctrl/ctrl_endpoints.h
			ctrl/ctrl_file.c
			ctrl/ctrl_file.h
			ctrl/ctrl_groups_ep.c
			ctrl/ctrl_objects_ep.c
			ctrl/ctrl_signal_ep.c
			ctrl/ctrl_steps_ep.c
			ctrl/ctrl_upload.c
			ctrl/ctrl_upload.h
			ctrl/ctrl_usrmeta_ep.c
			ctrl/ctrl_util.c
			ctrl/ctrl_util.h
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
			event/event.c
			event/event.h
			event/event_http_server.c
			event/event_http_server.h
			event/event_rest.c
			event/event_rest.h
			event/event_socket.c
			event/event_socket.h
			event/event_periodic.c
			event/event_periodic.h
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
			pantahub/pantahub.c
			pantahub/pantahub.h
			pantahub/pantahub_msg.c
			pantahub/pantahub_msg.h
			pantahub/pantahub_proto.c
			pantahub/pantahub_proto.h
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
			ubootab.c
			updater.c
			updater.h
			update/update.c
			update/update.h
			update/update_progress.c
			update/update_progress.h
			update/update_struct.h
			utils/base64.c
			utils/buildinfo.c
			utils/buildinfo.h
			utils/fitimg.c
			utils/fs.c
			utils/json.c
			utils/math.c
			utils/mtd.c
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
			wall.c
			wall.h
			wdt.c
			wdt.h
)
target_include_directories(pantavisor PRIVATE
	${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/utils
	${PANTAVISOR_RUNTIME_MBEDTLS_INCLUDE_DIR}
)
target_link_libraries(pantavisor
	${PANTAVISOR_RUNTIME_THTTP}
	${PANTAVISOR_RUNTIME_PICOHTTPPARSER}
	${PANTAVISOR_RUNTIME_MBEDTLS_LIBRARIES}
	${PANTAVISOR_RUNTIME_LXC}
	${PANTAVISOR_RUNTIME_ZLIB}
	${PANTAVISOR_RUNTIME_EVENT_LIBRARIES}
)

install(TARGETS pantavisor DESTINATION bin)

IF(PANTAVISOR_DEBUG)
target_compile_definitions(pantavisor PRIVATE PANTAVISOR_DEBUG)
ENDIF()

IF(NOT PANTAVISOR_DEFAULTS_SKIP_INSTALL)
## install basic filesystem skeleton
install(DIRECTORY skel/ DESTINATION /)
### ... insert defaults/
install(DIRECTORY defaults DESTINATION /etc/pantavisor)
ENDIF()

### install PVS secureboot files
IF(NOT PANTAVISOR_PVS_SKIP_INSTALL)
IF(DEFINED PANTAVISOR_PVS_DIR)
install(DIRECTORY ${PANTAVISOR_PVS_DIR}/ DESTINATION /etc/pantavisor/pvs/trust FILES_MATCHING PATTERN "*.crt")
ELSE()
install(DIRECTORY pvs/ DESTINATION /etc/pantavisor/pvs)
ENDIF()
ENDIF()

### install /init link if not appengine build
if(NOT PANTAVISOR_APPENGINE)
install(CODE "file(CREATE_LINK usr/bin/pantavisor ${CODE_INSTALL_BASE}/init SYMBOLIC)")
ENDIF()

### install scripts
if(PANTAVISOR_E2FSGROW_ENABLE)
install(FILES scripts/pv_e2fsgrow
	PERMISSIONS WORLD_READ WORLD_EXECUTE GROUP_READ GROUP_EXECUTE OWNER_READ OWNER_WRITE OWNER_EXECUTE
	DESTINATION /lib/pv/)
ENDIF()
install(FILES scripts/JSON.sh scripts/pvcrash
	PERMISSIONS WORLD_READ WORLD_EXECUTE GROUP_READ GROUP_EXECUTE OWNER_READ OWNER_WRITE OWNER_EXECUTE
	DESTINATION /lib/pv/)
install(DIRECTORY scripts/hooks_lxc-mount.d
	FILE_PERMISSIONS WORLD_READ WORLD_EXECUTE GROUP_READ GROUP_EXECUTE OWNER_READ OWNER_WRITE OWNER_EXECUTE
	DESTINATION /lib/pv)
install(PROGRAMS tools/pventer
			tools/fallbear-cmd
	DESTINATION /usr/bin)

add_executable(remount
			remount/remount.c
			utils/pvsignals.h utils/pvsignals.c
			utils/tsh.c utils/tsh.h
			utils/fs.c
			utils/json.c
			utils/str.c
)
target_compile_definitions(remount PUBLIC -DDISABLE_LOGSERVER)
target_include_directories(remount PRIVATE ${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/utils)
target_link_libraries(remount  ${PANTAVISOR_RUNTIME_THTTP})
install(TARGETS remount DESTINATION /lib/pv/hooks_lxc-mount.d)

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

ENDIF() # PANTAVISOR_RUNTIME

## PVTX section

set(PVTX_COMMON_SOURCES
	utils/pvsignals.h
	utils/pvsignals.c
	utils/tsh.c
	utils/fs.c
	pvtx/pvtx_utils/base64.c
	pvtx/pvtx_utils/sha256-internal.c
	pvtx/pvtx_utils/jsmn.c
	pvtx/pvtx_buffer.h
	pvtx/pvtx_buffer.c
	pvtx/pvtx_ctrl.c
	pvtx/pvtx_ctrl.h
	pvtx/pvtx_error.c
	pvtx/pvtx_error.h
	pvtx/pvtx_jsmn_utils.c
	pvtx/pvtx_jsmn_utils.h
	pvtx/pvtx_state.c
	pvtx/pvtx_state.h
	pvtx/pvtx_tar.c
	pvtx/pvtx_tar_formats.c
	pvtx/pvtx_tar.h
	pvtx/pvtx_tar_impl.h
	pvtx/pvtx_txn.c
	pvtx/pvtx_txn.h
	pvtx/pvtx.c
)

IF (PANTAVISOR_PVTX)

find_library(PANTAVISOR_PVTX_ZLIB z)

add_executable(pvtx
	${PVTX_COMMON_SOURCES}
)
target_compile_definitions(pvtx PUBLIC -DDISABLE_LOGSERVER)
target_include_directories(pvtx PRIVATE
	${CMAKE_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}/utils
)
target_link_libraries(pvtx ${PANTAVISOR_PVTX_ZLIB})
install(TARGETS pvtx DESTINATION /usr/bin)

ENDIF() # PANTAVISOR_PVTX

IF (PANTAVISOR_PVTX_STATIC)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")

find_library(PANTAVISOR_PVTX_STATIC_ZLIB z)

add_executable(pvtx-static
	${PVTX_COMMON_SOURCES}
)
target_compile_definitions(pvtx-static PUBLIC -DDISABLE_LOGSERVER)
target_include_directories(pvtx-static PRIVATE
	${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/utils
)
target_link_libraries(pvtx-static ${PANTAVISOR_PVTX_STATIC_ZLIB})
target_link_options(pvtx-static PRIVATE
	LINKER:-static
	-static
	-static-libgcc
)
set_target_properties(pvtx-static PROPERTIES
    LINK_SEARCH_END_STATIC 1 # Set to 1 (true)
)
install(TARGETS pvtx-static DESTINATION /usr/bin)

ENDIF() # PANTAVISOR_PVTX_STATIC

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

enable_testing()
add_test(pvtx ${CMAKE_CURRENT_SOURCE_DIR}/test/pvtx/pvtx.sh ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
