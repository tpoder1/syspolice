
PREFIX=/
NAME=police
OWNER=root
GROUP=root
BINDIR=$(PREFIX)/usr/sbin/
MANDIR=$(PREFIX)/usr/share/man/man1/
DOCDIR=$(PREFIX)/usr/share/doc/${NAME}-${VERSION}/
CFGDIR=$(PREFIX)/etc/
CRONDIR=$(PREFIX)/etc/cron.d/
INSTALL=install
export VISUAL:= vim

help:
		@echo "Build help:"
		@echo ""
		@echo "   make help            - this help"
		@echo "   make main            - prepare library and build client"
		@echo "   make install-client  - install client binary"
		@echo "   make install-server  - install server libs and server binary"
		@echo "   make tgz             - prepare and create instalation tarball"
		@echo "   make rpm             - build source and installable rpm packages"
		@echo ""


main:
		# build libs
		cd lib && perl Makefile.PL && make
		# create  the client executable by joining all libs into one file 
		rm -f bin/police-client
		echo '#!/usr/bin/perl -w' > bin/police-client
		cat lib/Police/Log.pm >> bin/police-client
		cat lib/Police/Scan/Dir.pm | grep -v "use Police::" >> bin/police-client
		cat bin/police-client-base | grep -v "use lib" | grep -v "use Police" >> bin/police-client
		chmod +x bin/police-client

install-clent: main
		
install-server: main
		
clean:
		cd lib && make clean && rm -f Makefile && rm -f Makefile.old && cd ..

VERSION="sss:wq"

VERSION:=$(shell ./bin/police -? | grep Version: | cut -f2 -d:  | cut -f2 -d" ")
tgz: 
		echo $(VERSION)
#        # create documentation files
#        pod2text < $(NAME) > RDBACKUP.txt
#        pod2man < $(NAME) > rdbackup.1
#        pod2html < $(NAME) > rdbackup.html
		# update version in specfile
		cp police.spec tmp.spec
		sed "s/%define version.*/%define version\t\t$(VERSION)/" < tmp.spec > police.spec
		rm tmp.spec

		# copy files into dist directory 	
		rm -rf                     $(NAME)-$(VERSION)
		mkdir                      $(NAME)-$(VERSION)
		mkdir                      $(NAME)-$(VERSION)/bin
		cp bin/police              $(NAME)-$(VERSION)/bin
		cp bin/police-client-base  $(NAME)-$(VERSION)/bin
		mkdir                      $(NAME)-$(VERSION)/lib
		cp lib/Makefile.PL         $(NAME)-$(VERSION)/lib
		mkdir                      $(NAME)-$(VERSION)/lib/Police
		cp lib/Police/*.pm         $(NAME)-$(VERSION)/lib/Police
		mkdir                      $(NAME)-$(VERSION)/lib/Police/Scan
		cp lib/Police/Scan/*.pm    $(NAME)-$(VERSION)/lib/Police/Scan
		cp Makefile                $(NAME)-$(VERSION)
		cp police.spec             $(NAME)-$(VERSION)

		# create the tar archive
		tar -czf $(NAME)-$(VERSION).tar.gz $(NAME)-$(VERSION)
		rm -rf $(NAME)-$(VERSION)

commit:	
		svn commit 

