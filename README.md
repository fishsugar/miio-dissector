# miio-dissector
Xiaomi Mi Home Binary Protocol Dissector for Wireshark.

# Requirements

- Wireshark 4.6.0 or above

# Install

Copy [miio.lua](miio.lua) and [libs/](libs) to [Wireshark plugin folder](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html).

# Usage
After installation, restart the Wireshark, open `Preferences` -> `Protocols` -> `MIIO` page, input the device token and save.

![](./screenshot.png)

# Documentation
[Xiaomi's MiHome Binary protocol](https://github.com/OpenMiHome/mihome-binary-protocol/blob/master/doc/PROTOCOL.md)

[Wireshark’s Lua API Reference Manual](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html)

[Lua编写Wireshark插件实战](https://www.zybuluo.com/natsumi/note/77991)
