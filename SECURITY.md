# 安全漏洞报告 / Security policy

## 如何报告

发现 RustROS 的安全漏洞，请发邮件到 **security@rustros.com**，不要在公开的 issue、讨论区或社交媒体上发布。

请尽量写明：

- 受影响的版本号（网页管理中显示的版本，或你安装的发布版本）
- 问题所在的部分（转发、NAT、规则组、网页管理、在线更新、安装脚本、网站等）
- 重现步骤，或能说明问题的最小示例
- 你看到的影响：例如越权访问、绕过规则、拒绝服务、数据泄露

## 我们的回应

- **3 个工作日内**确认收到并回复
- **7 天内**给出初步判断：是否确认、严重程度、预计修复时间
- 确认的漏洞按严重程度修复：严重的优先发布修复版本，修复发布后在发布记录中说明
- 修复发布前，请不要公开细节；如果 90 天内仍未修复，你可以自行决定是否公开
- 愿意署名的报告者，我们会在修复说明中致谢

## 范围

RustROS 系统本身、网页管理、在线更新与安装脚本（`https://rustros.com/install.sh`），以及 rustros.com 网站。支持的版本：最新正式版和最新版（latest）。

---

## Reporting a vulnerability

Please report security vulnerabilities in RustROS by email to **security@rustros.com**. Do not post them in public issues, discussions or on social media.

Please include, where you can:

- the affected version (as the web admin shows it, or the release you installed)
- the part concerned (forwarding, NAT, rule groups, web admin, online updates, the installer, the website)
- steps to reproduce, or a minimal example that shows the problem
- the impact you saw: for example access beyond rights, a rule bypassed, denial of service, data exposed

## What to expect

- an acknowledgement **within 3 working days**
- a first assessment **within 7 days**: confirmed or not, severity, and the expected time to a fix
- confirmed issues are fixed by severity; severe ones get a fix release first, and the fix is described in the release notes once it is out
- please keep details private until the fix is released; if it is not fixed within 90 days, disclosure is your decision
- reporters who wish to be named are credited in the fix notes

## Scope

The RustROS system, its web admin, online updates and the installer (`https://rustros.com/install.sh`), and the rustros.com website. Supported versions: the newest stable release and the newest release of any kind (latest).
