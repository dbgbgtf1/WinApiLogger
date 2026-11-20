# Windows 11 x64 API Logger

本项目实现 Windows 11 24H2（`10.0.26100.9974`）x64 API 日志记录器。
构建过程使用 `target_dlls/` 中指定的原始 DLL，嵌入目标进程内 logger，并生成：

- `build/WinApiLogger.sys`：WDM 控制驱动和入口安装器。
- `build/WinApiLoggerCli.exe`：静态链接的 stream 控制和读取客户端。
- `build/skipped_exports.csv`：所有未安装导出及跳过原因。
- `build/analysis.json`：完整构建元数据，包括从目标 DLL 文件名生成的规范系统路径。
- `build/rip_relative.csv`：所有 RIP-relative fixup 及其原目标 RVA。

## 目录与产物

- `target_dlls/`：实际 hook 目标 DLL。驱动只分析并 patch 这里的 DLL。
- `build/WinApiLogger.sys`：WDM 内核驱动。
- `build/WinApiLoggerCli.exe`：静态链接的管理和读取客户端。
- `build/analysis.json`：目标 DLL 身份和导出分析结果。
- `build/skipped_exports.csv`：未安装导出及跳过原因。
- `build/rip_relative.csv`：RIP-relative displacement 修正清单。
- `build/vm/WinApiLoggerTest.cer`：一次性测试签名生成的公钥证书。

## 1. 构建机前置条件

构建机需要：

- Windows 11 x64。
- Visual Studio 2022 或更新版本，并安装“使用 C++ 的桌面开发”。
- Windows 11 SDK/WDK `10.0.26100.0`，包括内核头文件、库和 `infverif.exe`。
- LLVM/Clang，默认路径为 `C:\Program Files\LLVM\bin`。
- Python 3，并安装构建依赖：

  ```powershell
  python -m pip install capstone pefile
  ```

- `target_dlls/` 中的 DLL 必须与目标系统的文件版本、时间戳、镜像大小和 SHA-256 匹配。

可先检查关键工具：

```powershell
Test-Path 'C:\Program Files\LLVM\bin\clang.exe'
Test-Path 'C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0'
python -c "import capstone, pefile; print('Python dependencies OK')"
```

## 2. 编译并运行主机测试

在仓库根目录打开管理员 PowerShell：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\build.ps1 -Test
```

构建会依次：

1. 校验三个 hook 目标 DLL 的身份。
2. 分析导出并过滤转发导出、数据导出和不安全入口。
3. 使用 Clang 构建 freestanding logger payload。
4. 使用 MSVC 构建驱动和 CLI。
5. 校验 INF、运行 Python 单元测试和 logger 运行时测试。
6. 重新生成 `compile_commands.json`。

如果 `target_dlls/` 和生成元数据都没有变化，可跳过重新分析：

```powershell
.\build.ps1 -SkipAnalyze
```

不要使用 `-SkipAnalyze` 绕过首次构建或替换 `target_dlls/` 后的分析。

正常完成后应存在：

```text
build\WinApiLogger.sys
build\WinApiLoggerCli.exe
build\analysis.json
build\skipped_exports.csv
build\rip_relative.csv
build\logger_payload.bin
```

驱动每次重新编译后都需要重新签名。

## 3. 测试签名

以下流程只适用于专用测试 VM。生产环境不要使用自签名测试证书。

在构建机执行：

```powershell
.\tools\sign_test_driver.ps1
```

它会：

- 创建两天有效的临时代码签名证书。
- 签署 `build\WinApiLogger.sys`。
- 导出公钥到 `build\vm\WinApiLoggerTest.cer`。
- 从构建机证书存储中删除私钥证书。

测试机必须满足：

- Secure Boot 已关闭。
- 管理员权限。
- 已启用 Windows test signing。

将以下文件复制到测试机，例如 `C:\WinApiLogger`：

```text
WinApiLogger.sys
WinApiLoggerCli.exe
WinApiLoggerTest.cer
analysis.json
vm_preflight.ps1
vm_smoke.ps1
```

在测试机管理员 PowerShell 中启用 test signing：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
C:\WinApiLogger\vm_preflight.ps1 -EnableTestSigning
shutdown /r /t 0
```

重启后再次检查：

```powershell
C:\WinApiLogger\vm_preflight.ps1
Get-Content C:\WinApiLogger\vm_preflight.json
```

预期：

```json
{
  "success": true,
  "is_admin": true,
  "secure_boot": false,
  "testsigning_enabled": true
}
```

导入测试证书：

```powershell
certutil.exe -addstore -f Root C:\WinApiLogger\WinApiLoggerTest.cer
certutil.exe -addstore -f TrustedPublisher C:\WinApiLogger\WinApiLoggerTest.cer
```

## 4. 安装驱动服务

当前仓库没有生成和签署 `WinApiLogger.cat`，因此推荐使用非 PnP 内核服务的直接安装命令：

```powershell
sc.exe create WinApiLogger type= kernel start= demand error= normal binPath= C:\WinApiLogger\WinApiLogger.sys DisplayName= WinApiLogger

sc.exe start WinApiLogger
sc.exe query WinApiLogger
```

在 catalog 未生成并签名前，不要改用 `pnputil /add-driver ... /install`。

最后一条命令应显示：

```text
STATE : 4  RUNNING
```

如果服务已存在，先确认没有活动目标，再使用：

```powershell
sc.exe stop WinApiLogger
sc.exe delete WinApiLogger
```

驱动默认不 hook 任何进程。设备对象只允许 SYSTEM 和本机 Administrators 访问，因此以下
CLI 命令都需要管理员权限。

## 5. 设置捕获目标并读取日志

添加目标进程镜像基名。匹配不区分大小写，只接受文件名，不接受完整路径：

```powershell
C:\WinApiLogger\WinApiLoggerCli.exe filter add notepad.exe
C:\WinApiLogger\WinApiLoggerCli.exe filter add ping.exe
```

Filter 只影响添加后创建的进程。启动目标：

```powershell
$p = Start-Process C:\Windows\System32\notepad.exe -PassThru
C:\WinApiLogger\WinApiLoggerCli.exe list
```

按 stream 持续读取：

```powershell
C:\WinApiLogger\WinApiLoggerCli.exe read --stream 1 --follow
```

实时观察所有活动流。`--module` 过滤输出中的 Hook 模块
`called <hook-module>!<api>`；`--caller` 过滤冒号前的调用者模块：

```powershell
C:\WinApiLogger\WinApiLoggerCli.exe watch --follow
C:\WinApiLogger\WinApiLoggerCli.exe watch --follow --module KernelBase --api CreateFileW
C:\WinApiLogger\WinApiLoggerCli.exe watch --follow --caller Notepad
C:\WinApiLogger\WinApiLoggerCli.exe watch --follow --module KernelBase --caller Notepad
C:\WinApiLogger\WinApiLoggerCli.exe watch --follow --pid 1234
```

`--module` 和 `--caller` 均不区分大小写，扩展名可省略。两个条件同时指定时使用 AND
关系。caller 名称最多保留 15 个 WCHAR，因此名称过长的模块可按 15 WCHAR 的截断名匹配。

清空 filter：

```powershell
C:\WinApiLogger\WinApiLoggerCli.exe filter reset
```

`filter reset` 不会撤销已 hook 进程；这些进程仍必须退出后驱动才能安全卸载。

## 6. 停止和卸载

不要在有活动目标流时停止驱动。先结束所有被 hook 的进程，再确认列表为空：

```powershell
C:\WinApiLogger\WinApiLoggerCli.exe list
```

该命令不应再返回目标 PID 或 StreamId。然后执行：

```powershell
sc.exe stop WinApiLogger
sc.exe delete WinApiLogger
```

驱动在仍有活动状态时采用 fail-closed 策略，强制停止可能触发蓝屏。若目标无法退出，应重启
测试 VM 清理，而不是反复尝试停止服务。

测试结束后可关闭 test signing：

```powershell
bcdedit.exe /set '{current}' testsigning off
shutdown /r /t 0
```

## 7. 自动化 VM 冒烟测试

复制文件并进入测试机后，可以直接运行：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
C:\WinApiLogger\vm_smoke.ps1 -Root C:\WinApiLogger
```

脚本会：

1. 检查管理员权限和 Windows 版本。
2. 校验 System32 DLL 与 `analysis.json` 一致。
3. 导入测试证书。
4. 创建并启动 `WinApiLogger` 服务。
5. 捕获 `ping.exe` 并读取 API 记录。
6. 验证目标退出后 stream 被删除。
7. 验证延迟读取返回 `STATUS_NOT_FOUND`。
8. 停止并删除驱动服务。

结果写入：

```text
C:\WinApiLogger\WinApiLogger-smoke.json
```

成功时 `success` 为 `true`，且 `steps` 中没有失败项。

## 8. 正式签名与分发

当前 `sc.exe create` 流程用于测试和内部部署。对外分发应：

1. 通过 Microsoft Hardware Dev Center/Partner Center 完成内核驱动签名。
2. 为 INF 生成并签署 catalog。
3. 将 `.sys`、`.inf`、`.cat` 作为完整驱动包分发。
4. 在目标 Windows 版本上重新验证 DLL 身份、导出分析和签名状态。

不要使用 `tools/sign_test_driver.ps1` 生成的文件进行生产分发。

## 安全模型

构建会拒绝 DLL 身份不匹配、转发导出或数据导出、首段指令包含 relocation、相对控制流、
ret、重叠导出以及越界范围的函数。首段中的 RIP-relative 操作数会记录其 `disp32` 偏移，
运行时按 stub 地址重新计算 displacement。每个入口在 patch 前都会核对构建期保存的完整
原始字节；任一 fixup、近地址可达性或入口写入失败都会放弃并回滚该模块，并把原因写入
stream 状态。

构建期还会检查每个 RIP-relative 目标是否落入同一模块中任意计划覆盖的入口区间，并验证所有近地址
候选是否能同时满足模块内全部 RIP fixup 和两段 `E9 rel32`。任一检查失败都会终止构建，
错误信息包含目标 DLL SHA-256、函数 RVA、目标 RVA 和搜索范围。替换 `target_dlls/` 后
不得用 `-SkipAnalyze` 绕过该错误；必须按新的 DLL 哈希、导出布局和 stub 地址策略完成
审查，并在 `tools/analyze_targets.py` 中增加精确到哈希的 target-specific 处理。
当前已审查的特例只有 ntdll SHA-256
`A0F81BF5C610C0FF0A550ADC020A58446F214790C748057BB575042E972E6A34` 中的
`0x124800`：其 `lea` 返回 `0x16AA40` 函数入口地址。特例要求 RVA、目标 RVA 和
指令助记符全部匹配，DLL 更新后不会自动沿用。

导出名 `KiUserExceptionDispatcher` 无论位于哪个目标 DLL、哪个 RVA，也无论其指令是否可由
RIP fixup 修正，都禁止安装。该入口用于把用户态异常送回分发器；如果日志路径自身触发异常，
hook 会递归进入异常分发器并最终耗尽线程栈。

每个目标进程使用一块私有 RW MDL，固定包含 64 字节 Context、64 字节队列头和 8,190
个 32 字节 Logger 记录槽。`READ_STREAM` 每次有记录可读时临时遍历目标 PEB，把 caller
绝对地址解析成 16 WCHAR 的模块基名和 RVA；临时快照在响应填充完成后释放。进程退出后
stream 立即从活动列表移除，未读记录直接丢弃；之后对旧
StreamId 的 `READ_STREAM` 返回 `STATUS_NOT_FOUND`。

## 模块目录

- `target_dlls/` 决定实际安装 hook 的 DLL，同时为 reader 生成 hook 模块名称和 API
  名称表。当前仍只有 `ntdll.dll`、`KernelBase.dll` 和 `kernel32.dll`。
- caller 模块名称不维护静态目录。driver 在读取时接受 PEB 中任意已加载映像，输出去掉
  扩展名并最多保留 15 WCHAR；这个名称仅用于诊断，不作为安全信任判断。
- hook 目标 ID 0、1、2 保持固定。日志格式为：

  ```text
  {pid}.{tid} {caller}:0x{caller_rva:X} called {hook_module}!{hook_function}
  {pid}.{tid} unknown-0x{caller_va:X} called {hook_module}!{hook_function}
  ```
