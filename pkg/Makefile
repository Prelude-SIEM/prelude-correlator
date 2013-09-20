PKGNAME = prelude-correlator
OUT_DIR = out
PKG_DIR = pkgdir

clean:
	rm -rf $(OUT_DIR) $(PKG_DIR)

$(PKG_DIR):
	mkdir $(PKG_DIR)

$(OUT_DIR):
	mkdir $(OUT_DIR)

sdist: | $(PKG_DIR) $(OUT_DIR)
	(cd ..;	python setup.py sdist)
	cp ../dist/$(PKGNAME)-*.tar.gz $(OUT_DIR)/

rpm_prepare: sdist
	rm -rf $(PKG_DIR)/rpm
	mkdir -p $(PKG_DIR)/rpm/BUILD $(PKG_DIR)/rpm/BUILDROOT $(PKG_DIR)/rpm/RPMS $(PKG_DIR)/rpm/SOURCES $(PKG_DIR)/rpm/SPEC $(PKG_DIR)/rpm/SRPMS
	cp $(OUT_DIR)/$(PKGNAME)-*.tar.gz $(PKG_DIR)/rpm/SOURCES/

rhel6_prepare: rpm_prepare
	rm -rf $(OUT_DIR)/rhel6
	mkdir $(OUT_DIR)/rhel6
	cp rhel6/$(PKGNAME).spec $(PKG_DIR)/rpm/SPEC/
	cp rhel6/$(PKGNAME).init $(PKG_DIR)/rpm/SOURCES/

rhel6: rhel6_prepare
	rpmbuild -ba --define "_topdir $(CURDIR)/$(PKG_DIR)/rpm" \
                     --define "_sourcedir %{_topdir}/SOURCES" \
                     --define "_specdir %{_topdir}/SPEC" \
                     --define "_rpmdir %{_topdir}/RPMS" \
                     --define "_srcrpmdir %{_topdir}/SRPMS" \
                     --define "_tmppath %{_topdir}/BUILDROOT" \
                     --define "_builddir %{_topdir}/BUILD" \
                     --define "dist .el6" \
                     $(PKG_DIR)/rpm/SPEC/$(PKGNAME).spec
	mv $(PKG_DIR)/rpm/RPMS $(OUT_DIR)/rhel6
	mv $(PKG_DIR)/rpm/SRPMS $(OUT_DIR)/rhel6

