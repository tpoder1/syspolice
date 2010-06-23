%define name		police
%define version		2.1.3a
%define release		1

Name:				%{name}
Summary:			A simple disk to disk backup system based on the rsync 
Version:			%{version}
Release:			%{release}
License:			GPL
Group:				Development/Other
URL:				http://code.google.com/p/syspolice/
Source:				%{name}-%{version}.tar.gz
Requires:			tar, gzip
BuildArch:			noarch
Buildroot:			%{_tmppath}/%{name}-buildroot
Packager:			Tomas Podermanski <tpoder@cis.vutbr.cz>

%description
The police system simplyfies the management of the unix base 
systems with following features: 
 - unified instalations, instalation templates 
 - security checks 
 - bulk maintains and updates 
 - backuping of configuration files 
 - the file system checks against to the predefined 
   package repository 

web: http://code.google.com/p/syspolice/

%package server
%description server
The server side of the police system. This package
must be installed only on the server side. The server
part runs all process, manage files and connect to the 
clients where the police-client package is instaled. 

%package client
%description client
The client side of the police system. This package
shoul be installed on both client and server.

%prep 

%setup

%install server
make PREFIX=$RPM_BUILD_ROOT/ install-server

%install server
make PREFIX=$RPM_BUILD_ROOT/ install-client

%files  
%defattr(-,root,root)

%files  server
/usr/bin/police
%config /etc/cron.d/police.cron
#%doc /usr/share/man/man1/police.1.gz

%files client
/usr/sbin/police-client


%changelog

