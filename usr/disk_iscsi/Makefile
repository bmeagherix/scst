#
#  disk_iscsi disk_tgt user space handlder
#
#  Copyright (C) 2023 Brian Meagher <brian.meagher@ixsystems.com>
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation, version 2
#  of the License.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU General Public License for more details.

ifndef PREFIX
        PREFIX=/usr/local
endif

SHELL=/bin/bash

SRCS_F = scst_disk_session.c
OBJS_F = $(SRCS_F:.c=.o)

SCST_INC_DIR := $(shell if [ -e "$$PWD/../../scst" ];			\
                  then echo "$$PWD/../../scst/include";			\
                  else echo "$(DESTDIR)$(PREFIX)/include/scst"; fi)
DEBUG_INC_DIR := ../include
INSTALL_DIR := $(DESTDIR)$(PREFIX)/bin/scst

CFLAGS += -O2 -Wall -Wextra -Wno-unused-parameter -Wstrict-prototypes \
	-I$(SCST_INC_DIR) -I$(DEBUG_INC_DIR) -D_GNU_SOURCE -D__USE_FILE_OFFSET64 \
	-D__USE_LARGEFILE64
PROGS = scst-disk-session
LIBS = -lpthread

CFLAGS += -Wextra -Wno-unused-parameter
CFLAGS += $(LOCAL_CFLAGS)

-include ../../scst/build_mode

# echo := $(shell echo "usr/fileio build mode: $(BUILD_MODE)" >& 2)

BUILD_MODE_CFLAGS_ = -DTRACING -DDEBUG -DEXTRACHECKS \
	-fno-inline -fno-inline-functions
BUILD_MODE_CFLAGS_RELEASE = -DTRACING
BUILD_MODE_CFLAGS_PERF =
CFLAGS += $(BUILD_MODE_CFLAGS_$(BUILD_MODE))


all: $(PROGS)

scst-disk-session: .depend_f $(OBJS_F)
	$(CC) $(OBJS_F) $(LIBS) $(LOCAL_LD_FLAGS) -o $@

%.o: %.c Makefile
	$(CC) -c -o $(@) $(CFLAGS) $(<)

.depend_f:
	$(CC) -M $(CFLAGS) $(SRCS_F) >$(@)

#.depend_c:
#	$(CC) -M $(CFLAGS) $(SRCS_C) >$(@)

install: all
	install -d $(INSTALL_DIR)
	install -m 755 $(PROGS) $(INSTALL_DIR)

uninstall:
	rm -f $(INSTALL_DIR)/$(PROGS)

clean:
	rm -f *.o $(PROGS) .depend*

extraclean: clean
	rm -f *.orig *.rej

2release:
	-$(MAKE) clean

2debug:
	-$(MAKE) clean

2perf:
	-$(MAKE) clean

release-archive:
	../../scripts/generate-release-archive scst-disk-session "$$(sed -n 's/^#define[[:blank:]]VERSION_STR[[:blank:]]*\"\([^\"]*\)\".*/\1/p' ../include/version.h)"

.PHONY: all install uninstall clean extraclean 2release 2debug 2perf
