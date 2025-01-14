# 内存修改器

这是一个用于修改Windows操作系统上进程内存的C++项目。该工具可以帮助用户列出当前所有进程、通过目标值修改内存数据，或者通过内存地址修改内存数据。

## 功能

- 列出当前所有进程及其PID。
- 通过进程名获取进程ID。
- 扫描进程内存并查找指定值。
- 修改进程内存中的数据。
- 提供交互式菜单供用户选择操作模式。

## 使用方法

1. 克隆或下载此项目到本地。
2. 使用支持C++的IDE（如Visual Studio）打开项目。
3. 编译并运行程序。
4. 根据菜单提示选择相应的操作模式。

## 菜单选项

- **1 -> 列出当前所有进程**
  - 列出当前系统上所有正在运行的进程及其PID。
  
- **2 -> 通过【目标值】修改内存数据**
  - 输入目标值和进程名，程序将扫描进程内存并查找所有匹配的内存地址。
  - 用户可以进一步筛选内存地址，直到找到唯一的地址。
  - 输入要修改的新数据，程序将自动更新内存中的值。

- **3 -> 通过【内存地址】修改内存数据**
  - 输入内存地址和进程名，程序将直接修改指定内存地址的数据。
  - 输入要修改的新数据，程序将自动更新内存中的值。

## 注意事项

- 请确保您有足够的权限来访问和修改目标进程的内存。
- 修改系统进程的内存可能会导致系统不稳定或崩溃，请谨慎操作。
- 本工具仅供学习和研究使用，请勿用于非法用途。

## 编译环境

- 操作系统：Windows
- 编译器：支持C++11及以上标准的编译器，如Visual Studio 2019及以上版本。

## 贡献

如果您有任何建议或改进意见，请随时提交Pull Request或创建Issue。

## 许可

本项目遵循 GPLv3.0 许可证。请查看LICENSE文件了解更多信息。

