ifdef MOSQ_USE_VALGRIND
	ifeq ($(MOSQ_USE_VALGRIND),callgrind)
		SANITIZER_COMMAND=valgrind -q --tool=callgrind --log-file=$${t}.vglog
	endif
	ifeq ($(MOSQ_USE_VALGRIND),massif)
		SANITIZER_COMMAND=valgrind -q --tool=massif --log-file=$${t}.vglog
	endif
	ifeq ($(MOSQ_USE_VALGRIND),failgrind)
		SANITIZER_COMMAND=fg-helper
	endif
	ifndef SANITIZER_COMMAND
		SANITIZER_COMMAND=valgrind -q --trace-children=yes --leak-check=full --show-leak-kinds=all --log-file=$${t}.vglog
	endif
else
	SANITIZER_COMMAND=
endif
