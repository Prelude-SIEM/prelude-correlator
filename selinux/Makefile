TARGETS?= prelude-correlator
MODULES?=${TARGETS:=.pp.bz2}

all: ${TARGETS:=.pp.bz2}

%.pp.bz2: %.pp
	@echo Compressing $^ -\ $@
	bzip2 -9 $^

%.pp: %.te
	make -f /usr/share/selinux/devel/Makefile $@

clean:
	make -f /usr/share/selinux/devel/Makefile clean
	rm -f *.pp.bz2
