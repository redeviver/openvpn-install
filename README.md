##openvpn-install
OpenVPN [road warrior](http://en.wikipedia.org/wiki/Road_warrior_%28computing%29) installer for Debian, Ubuntu and CentOS.

This script will let you setup your own VPN server in no more than a minute, even if you haven't used OpenVPN before. It has been designed to be as unobtrusive and universal as possible.

###Installation
Run the script and follow the assistant:

```
git clone -o github https://github.com/richardskumat/openvpn-install
bash -x openvpn-install/openvpn-install.sh
```

An automated version of the script is ovpn2.sh.

It defines a few variables in the following values:

```
IP=$IP
PORT=1194
DNS=1
CLIENT="$(hostname)"
IPRANGE="10.88.88.0"
IPNETMASK="255.255.255.0"
IPCIDR='/24'
```

Explanation:

```
IP=your external public, the result of wget going to ipv4.icanhazip.com
PORT=1194, the default value in the manual script
DNS=1, the first choice in the "What DNS do you want to use with the VPN" question.
CLIENT=by default is set to the hostname of the server, such as "ip-172-22-23-24" for example on AWS VM-s.
IPRANGE=10.88.88.0, a different range from the default values in the manual script.
IPNETMASK=255.255.255.0 is the value of a /24 IP range, so 10.88.88.0-10.88.88.255
IPCIDR=/24 by default
```

after the:

```
echo 'Welcome to this quick OpenVPN "road warrior" installer'
```

line.

Once it ends, you can run it again to add more users, remove some of them or even completely uninstall OpenVPN.

