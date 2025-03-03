cmake_minimum_required(VERSION 3.10)

# project details
project(VoteApp VERSION 1.0)
set(VOTER_EXEC_NAME vote_voter)
set(REGISTRAR_EXEC_NAME vote_registrar)
set(TALLYER_EXEC_NAME vote_tallyer)
set(ARBITER_EXEC_NAME vote_arbiter)
set(LIBRARY_NAME vote_app_lib)
set(LIBRARY_NAME_SHARED vote_app_lib_shared)
set(LIBRARY_NAME_TA vote_app_lib_ta)

# turn on gdb
set(CMAKE_BUILD_TYPE Debug)

# packages
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
include(Boost)
# include(Cryptopp)
include(CTest)
include(Doctest)
include(Documentation)
include(Warnings)
include(Curses)
include(Sqlite3)

# add shared libraries
set(SOURCES_SHARED
  src-shared/config.cxx
  src-shared/messages.cxx
  src-shared/logger.cxx
  src-shared/util.cxx
  src-shared/keyloaders.cxx)
add_library(${LIBRARY_NAME_SHARED} ${SOURCES_SHARED})
target_include_directories(${LIBRARY_NAME_SHARED} PUBLIC ${PROJECT_SOURCE_DIR}/include-shared)
target_link_libraries(${LIBRARY_NAME_SHARED} PUBLIC doctest)
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE cryptopp)
# target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE cryptopp-shared)
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE sqlite3)
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE ${Boost_LIBRARIES})
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE ${CURSES_LIBRARIES})

# add student libraries
set(SOURCES
  src/pkg/election.cxx
  src/pkg/voter.cxx
  src/pkg/registrar.cxx
  src/pkg/tallyer.cxx
  src/pkg/arbiter.cxx
  src/drivers/cli_driver.cxx
  src/drivers/crypto_driver.cxx
  src/drivers/db_driver.cxx
  src/drivers/network_driver.cxx
  src/drivers/repl_driver.cxx)
add_library(${LIBRARY_NAME} ${SOURCES})
target_include_directories(${LIBRARY_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include-shared ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(${LIBRARY_NAME} PRIVATE ${LIBRARY_NAME_SHARED})

# add ta libraries
if ( "$ENV{CS1515_TA_MODE}" STREQUAL "on" )
  set(SOURCES_TA
    src-ta/pkg/election.cxx
    src-ta/pkg/voter.cxx
    src-ta/pkg/registrar.cxx
    src-ta/pkg/tallyer.cxx
    src-ta/pkg/arbiter.cxx
    src-ta/drivers/cli_driver.cxx
    src-ta/drivers/crypto_driver.cxx
    src-ta/drivers/db_driver.cxx
    src-ta/drivers/network_driver.cxx
    src-ta/drivers/repl_driver.cxx)
  add_library(${LIBRARY_NAME_TA} ${SOURCES_TA})
  target_include_directories(${LIBRARY_NAME_TA} PUBLIC ${PROJECT_SOURCE_DIR}/include-shared ${PROJECT_SOURCE_DIR}/include-ta)
  target_link_libraries(${LIBRARY_NAME_TA} PRIVATE ${LIBRARY_NAME_SHARED})
endif()

# add voter executables
if ( "$ENV{CS1515_TA_MODE}" STREQUAL "on" )
  add_executable(${VOTER_EXEC_NAME} src-ta/cmd/voter.cxx)
  target_link_libraries(${VOTER_EXEC_NAME} PRIVATE ${LIBRARY_NAME_TA})
else()
  add_executable(${VOTER_EXEC_NAME} src/cmd/voter.cxx)
  target_link_libraries(${VOTER_EXEC_NAME} PRIVATE ${LIBRARY_NAME})
endif()

# add register server executables
if ( "$ENV{CS1515_TA_MODE}" STREQUAL "on" )
  add_executable(${REGISTRAR_EXEC_NAME} src-ta/cmd/registrar.cxx)
  target_link_libraries(${REGISTRAR_EXEC_NAME} PRIVATE ${LIBRARY_NAME_TA})
else()
  add_executable(${REGISTRAR_EXEC_NAME} src/cmd/registrar.cxx)
  target_link_libraries(${REGISTRAR_EXEC_NAME} PRIVATE ${LIBRARY_NAME})
endif()

# add voting server executables
if ( "$ENV{CS1515_TA_MODE}" STREQUAL "on" )
  add_executable(${TALLYER_EXEC_NAME} src-ta/cmd/tallyer.cxx)
  target_link_libraries(${TALLYER_EXEC_NAME} PRIVATE ${LIBRARY_NAME_TA})
else()
  add_executable(${TALLYER_EXEC_NAME} src/cmd/tallyer.cxx)
  target_link_libraries(${TALLYER_EXEC_NAME} PRIVATE ${LIBRARY_NAME})
endif()

# add arbiter executables
if ( "$ENV{CS1515_TA_MODE}" STREQUAL "on" )
  add_executable(${ARBITER_EXEC_NAME} src-ta/cmd/arbiter.cxx)
  target_link_libraries(${ARBITER_EXEC_NAME} PRIVATE ${LIBRARY_NAME_TA})
else()
  add_executable(${ARBITER_EXEC_NAME} src/cmd/arbiter.cxx)
  target_link_libraries(${ARBITER_EXEC_NAME} PRIVATE ${LIBRARY_NAME})
endif()

# properties
set_target_properties(
  ${LIBRARY_NAME}
  ${VOTER_EXEC_NAME}
  ${REGISTRAR_EXEC_NAME}
  ${TALLYER_EXEC_NAME}
  ${ARBITER_EXEC_NAME}
    PROPERTIES
      CXX_STANDARD 20
      CXX_STANDARD_REQUIRED YES
      CXX_EXTENSIONS YES
)

# ta properties
if ( "$ENV{CS1515_TA_MODE}" STREQUAL "on" )
  set_target_properties(
    ${LIBRARY_NAME_TA}
        PROPERTIES
          CXX_STANDARD 20
          CXX_STANDARD_REQUIRED YES
          CXX_EXTENSIONS YES
  )
endif()

# add tests
add_subdirectory(test)
add_custom_target(check ./test.sh)
