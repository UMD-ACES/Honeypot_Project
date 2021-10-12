# Honeypot_Architecture

See [Wiki](https://github.com/UMD-ACES/Honeypot_Architecture/wiki)

To use the firewall, you may need to enable the following kernel module:

```shell
modprobe br_netfilter
sysctl -p /etc/sysctl.conf
```
