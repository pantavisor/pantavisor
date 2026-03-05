cmake_minimum_required(VERSION 3.0)

project(pv-devicepass VERSION 1.0)

find_library(LIBEVENT_LIB event)
find_library(PICOHTTPPARSER_LIB picohttpparser)
find_library(THTTP_LIB thttp)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}/../utils
)

add_executable(pv-devicepass
    pv-devicepass.c
    agent-ops.c
    ctrl-client.c
    proxy.c
    tunnel.c
    ../utils/json.c
    ../utils/str.c
)

target_link_libraries(pv-devicepass
    ${LIBEVENT_LIB}
    event_extra
    ${PICOHTTPPARSER_LIB}
    ${THTTP_LIB}
)

install(TARGETS pv-devicepass
    DESTINATION bin/
)

# keccak256sum — self-contained Keccak-256 hash, no library deps
add_executable(keccak256sum keccak256sum.c)
install(TARGETS keccak256sum DESTINATION bin/)

# ethsign — secp256k1 ECDSA tools using mbedtls
find_library(MBEDCRYPTO_LIB mbedcrypto)
add_executable(ethsign ethsign.c)
target_link_libraries(ethsign ${MBEDCRYPTO_LIB})
install(TARGETS ethsign DESTINATION bin/)

# devicepass-cli shell scripts
install(PROGRAMS scripts/devicepass-cli DESTINATION bin/)
install(FILES
    scripts/lib/config.sh
    scripts/lib/display.sh
    scripts/lib/identity.sh
    scripts/lib/signing.sh
    DESTINATION lib/devicepass/
)
install(FILES
    scripts/lib/guardian/common.sh
    scripts/lib/guardian/claim.sh
    scripts/lib/guardian/list.sh
    scripts/lib/guardian/status.sh
    scripts/lib/guardian/fund.sh
    scripts/lib/guardian/balance.sh
    scripts/lib/guardian/transfer.sh
    scripts/lib/guardian/revoke.sh
    DESTINATION lib/devicepass/guardian/
)
