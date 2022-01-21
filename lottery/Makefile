.PHONY: all clean
all: | build
	$(MAKE) -C build/
clean: | build
	$(MAKE) -C build/ clean

%: | build
	$(MAKE) -C $@

build:
	mkdir build
	cd build && qmake-qt5 ..
