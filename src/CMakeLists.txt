
set(MSD_LITE_BIN	msd_lite.c
			msd_lite_stat_text.c
			stream_sys.c
			liblcb/src/net/socket.c
			liblcb/src/net/socket_address.c
			liblcb/src/net/socket_options.c
			liblcb/src/net/utils.c
			liblcb/src/proto/http.c
			liblcb/src/proto/http_server.c
			liblcb/src/threadpool/threadpool.c
			liblcb/src/threadpool/threadpool_msg_sys.c
			liblcb/src/threadpool/threadpool_task.c
			liblcb/src/utils/cmd_line_daemon.c
			liblcb/src/utils/sys.c
			liblcb/src/utils/sys_res_limits_xml.c
			liblcb/src/utils/buf_str.c
			liblcb/src/utils/info.c
			liblcb/src/utils/ring_buffer.c
			liblcb/src/utils/xml.c)

add_executable(msd_lite ${MSD_LITE_BIN})
target_compile_definitions(msd_lite PRIVATE -DHTTP_SRV_XML_CONFIG)
target_compile_definitions(msd_lite PRIVATE -DSOCKET_XML_CONFIG)
target_compile_definitions(msd_lite PRIVATE -DTHREAD_POOL_SETTINGS_XML)
set_target_properties(msd_lite PROPERTIES LINKER_LANGUAGE C)
target_link_libraries(msd_lite ${CMAKE_REQUIRED_LIBRARIES} ${CMAKE_EXE_LINKER_FLAGS})

install(TARGETS msd_lite RUNTIME DESTINATION bin)
