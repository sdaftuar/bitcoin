# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_executable(dataprinter dataprinter.cpp)

target_link_libraries(dataprinter
  bitcoin_node
)

add_executable(printdb printdb.cpp)

target_link_libraries(printdb
  bitcoin_node
)

add_executable(combinedata combinedata.cpp)

target_link_libraries(combinedata
  bitcoin_node
)
