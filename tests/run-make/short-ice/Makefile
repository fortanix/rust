include ../tools.mk

# ignore-windows

export LD_LIBRARY_PATH := $(HOST_RPATH_DIR)
export RUSTC := $(RUSTC_ORIGINAL)
export TMPDIR := $(TMPDIR)

all:
	bash check.sh
