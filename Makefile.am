SUBDIRS = src debian

systemddir = /lib/systemd/system
dist_systemd_DATA = wilqifstats.service

deb: dist
	rm -rf dpkg-deb
	mkdir dpkg-deb
	cd dpkg-deb && tar xf ../$(distdir).tar.gz
	cd dpkg-deb/$(distdir) && dpkg-buildpackage -us -uc

