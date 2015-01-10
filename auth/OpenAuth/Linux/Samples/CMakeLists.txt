option (PROPRIETARY_GG "Use proprietary GlobalGrid distribution?" ON)
add_executable(distauth GGDNS.cpp GlobalGrid.cpp)
if(PROPRIETARY_GG)
set (EXTRA_LIBS ${EXTRA_LIBS} GlobalGrid)
include_directories("globalgrid" "${PROJECT_BINARY_DIR}" ".")

endif(PROPRIETARY_GG)
target_link_libraries(distauth OAuth uuid ${EXTRA_LIBS})
