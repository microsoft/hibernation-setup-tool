Name:           hibernation-setup-tool
Version:        1.0.9
Release:        0%{?dist}
Summary:        Azure Hibernation Setup Tool

License:        MIT
URL:            https://github.com/microsoft/%{name}
Source0:        %{name}_%{version}.tar.gz

%description
Sets up an Azure VM for hibernation, by creating and maintaining a swap file with the proper size, setting up bootloader parameters, etc.

%prep
%setup -n %{name}_%{version}

%install
rm -rf $RPM_BUILD_ROOT
%make_install

%post
%systemd_post hibernation-setup-tool.service
   systemctl daemon-reload
   systemctl start hibernation-setup-tool.service
   systemctl enable hibernation-setup-tool.service

%files
/lib/systemd/system/hibernation-setup-tool.service
/usr/sbin/hibernation-setup-tool

%changelog
* Wed Aug 24 2022 Pavan Rachapudy <vrachapu@microsoft.com> - %{version}
- Initial release 
