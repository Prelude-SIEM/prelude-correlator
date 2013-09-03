%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

Name: prelude-correlator
Epoch:   1
Version: 1.0.2
Release: 1%{?dist}
Summary: Real time correlator of events received by Prelude Manager

Group: Applications/Internet
License: GPLv2+
URL: http://www.prelude-ids.com
Source0: http://www.prelude-ids.com/download/releases/prelude-correlator/%{name}-%{version}.tar.gz
Source1: prelude-correlator.init

Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n) 
BuildRequires: python-devel python-setuptools
Requires(pre)   : /usr/sbin/useradd
Requires(post)  : /sbin/chkconfig
Requires(preun) : /sbin/chkconfig
Requires(preun) : /sbin/service
Requires(postun): /sbin/service
Requires: libprelude-python >= 0.9.24
Requires: python-setuptools
BuildArch: noarch


%description
Prelude-Correlator allows conducting multi-stream correlations
thanks to a powerful programming language for writing correlation
rules. With any type of alert able to be correlated, event
analysis becomes simpler, quicker and more incisive. This 
correlation alert then appears within the Prewikka interface
and indicates the potential target information via the set of
correlation rules. 

%prep
%setup -q

%build

%install
rm -rf %{buildroot}
%{__python} setup.py install -O1 --root=%{buildroot} 
mkdir -p %{buildroot}%{_initrddir}
install -m 755 %SOURCE1 %{buildroot}%{_initrddir}/%{name}

%clean
rm -rf %{buildroot}


%post
/sbin/chkconfig --add %{name}


%preun
if [ $1 = 0 ]; then
 /sbin/service %{name} stop > /dev/null 2>&1 || :
 /sbin/chkconfig --del %{name}
fi


%postun
if [ "$1" -ge "1" ]; then
 /sbin/service %{name} condrestart >/dev/null 2>&1 || :
fi


%files
%defattr(-,root,root,-)
%doc AUTHORS COPYING NEWS HACKING.README docs/sample-plugin
%dir %attr(0700,root,root) %{_sysconfdir}/%{name}
%config(noreplace) %attr(0644,root,root) %{_sysconfdir}/%{name}/%{name}.conf
%{_initrddir}/%{name}
%{_bindir}/%{name}
%dir %attr(0755,root,root) %{_var}/lib/%{name}
%{_var}/lib/%{name}/*
%{python_sitelib}/PreludeCorrelator/
%{python_sitelib}/prelude_correlator*.egg-info

%changelog
* Thu Aug 10 2012 Antoine Luong <antoine.luong@c-s.fr> - 1.0.1-2
- Added missing dependency to python-setuptools
- Fixed #517 : Prelude Correlator not starting (SELinux)

* Wed Jun 15 2011 Vincent Quéméner <vincent.quemener@c-s.fr> - 1.0.0-4
- Rebuilt for RHEL6

* Wed Feb 09 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1:1.0.0-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Wed Jul 21 2010 David Malcolm <dmalcolm@redhat.com> - 1:1.0.0-2
- Rebuilt for https://fedoraproject.org/wiki/Features/Python_2.7/MassRebuild

* Sun May 02 2010 Steve Grubb <sgrubb@redhat.com> - 1.0.0-1
- New upstream release

* Tue Mar 09 2010 Steve Grubb <sgrubb@redhat.com> - 1.0.0rc4-1
- New upstream release

* Mon Feb 01 2010 Steve Grubb <sgrubb@redhat.com> - 1.0.0rc2-1
- New upstream release

* Tue Nov 03 2009 Steve Grubb <sgrubb@redhat.com> - 0.9.0-0.10.beta8
- New beta release

* Sun Jul 26 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.9.0-0.9.beta6
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Fri Jul 10 2009 Steve Grubb <sgrubb@redhat.com> 0.9.0-0.8.beta6
- New beta release

* Mon Mar 02 2009 Steve Grubb <sgrubb@redhat.com> 0.9.0-0.7.beta3
- Fix bz#484361 Error message regarding missing arguments lua ruleset

* Thu Feb 26 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.9.0-0.6.beta3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Sat Dec 05 2008 Steve Grubb <sgrubb@redhat.com> 0.9.0-0.5.beta3
- Fix bz#469824 Correct brute force correlation rules
- Add signal header to prelude-correlator.c so it builds correctly bz 474698
- Include unowned /usr/include/prelude-correlator directory

*Fri Jul 11 2008 Steve Grubb <sgrubb@redhat.com> 0.9.0-0.3.beta3
- New beta release

*Thu Jul 03 2008 Steve Grubb <sgrubb@redhat.com> 0.9.0-0.1.beta2
- Initial packaging

