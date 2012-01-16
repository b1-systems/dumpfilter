# Copyright (c) 2011 B1 Systems GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.
 
# norootforbuild
 
Name:       dumpfilter
Version:    0.2.0
Release:    2
License:    GPLv2
Summary:    Compresses core dumps and ensures free disk space
Group:      System
Source:     dumpfilter-%{version}.tar.gz
BuildRoot:  %{_tmppath}/%{name}-%{version}-build
PreReq:     %insserv_prereq
Requires:   python >= 2.6, zlibc
BuildRequires: cmake, gcc
BuildArch:  noarch
 
%description
Dumpfilter is an advanced core dump filter that allows more control of systemwide
coredumps of crashed processes.
- writes a info file with informations about the dumped process
 - contains gdb created backtrace
- coredumps can be gzip compressed, increases dumping speed on nfs drives
- ensures enough free space remains on target filesystem
 
%prep
%setup -q

%build
cmake -DCMAKE_SKIP_RPATH=ON \
      -DCMAKE_INSTALL_PREFIX=%{_prefix}
%{__make} %{?jobs:-j%jobs}

%install
#install -m 0755 $RPM_SOURCE_DIR/src/dumpfilter.init $RPM_BUILD_ROOT/etc/init.d/dumpfilter
#install -m 0755 $RPM_ROOT_DIR/src/dumpfilter.py $RPM_BUILD_ROOT/usr/sbin/dumpfilter
#install $RPM_ROOT_DIR/src/dumpfilter.ini $RPM_BUILD_ROOT/etc/dumpfilter/dumpfilter.ini
#install $RPM_ROOT_DIR/src/dumpfilter.gdb $RPM_BUILD_ROOT/etc/dumpfilter/dumpfilter.gdb
%{__make} DESTDIR=%{buildroot} install
 
%clean
%{?buildroot:%__rm -rf "%{buildroot}"}
 
%post
%{insserv_force_if_yast dumpfilter}
/etc/init.d/dumpfilter start
 
%postun
%insserv_cleanup
 
%preun
%stop_on_removal

%files
%defattr(-,root,root)
/etc/init.d/dumpfilter
%dir /etc/dumpfilter
%config /etc/dumpfilter/*
/usr/sbin/dumpfilter
 
%changelog
