Summary: Display stack trace of a running process
Name: pstack
Version: 1.2
Release: 3
Copyright: GPL
Group: Development/Debuggers
Source: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-root
ExclusiveArch: %{ix86}

%description
pstack dumps a stack trace for a process, given the pid of that
process.  If the process named is part of a thread group, then all the threads
in the group are traced.

%prep
%setup -q

%build
make

%install
rm -rf $RPM_BUILD_ROOT
make install BINDIR=%{buildroot}%{_bindir} MANDIR=%{buildroot}%{_mandir}

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc COPYING README VERSION
%{_bindir}/pstack
%{_mandir}/man1/*

%changelog
* Wed Nov 12 2003 Roland McGrath <roland@redhat.com> 1.2-3
- updated linuxthreads support for newer linuxthreads internals (#107305)
- avoid buffer overflow in symbol printing (#109642)

* Thu Sep 18 2003 Jakub Jelinek <jakub@redhat.com> 1.1-7
- don't crash if one of shared libraries has stripped .symtab/.strtab
  (#98162)

* Mon Feb 24 2003 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Sat Feb 22 2003 Jakub Jelinek <jakub@redhat.com>
- rebuilt

* Fri Jun 21 2002 Tim Powers <timp@redhat.com>
- automated rebuild

* Tue May 28 2002 Jakub Jelinek <jakub@redhat.com>
- build on x86 only

* Mon Feb 25 2002 Preston Brown <pbrown@redhat.com>
- initial packaging
