# 小鸡探针面板


## 快速安装指令

```bash
curl -L https://raw.githubusercontent.com/jwjccc/xiaoji-dashboard/main/scripts/install-panel.sh -o install-panel.sh && chmod +x install-panel.sh && env PROBE_REPO_URL=https://github.com/jwjccc/xiaoji-dashboard.git PROBE_REF=main PROBE_PORT=8080 ./install-panel.sh
```

卸载面板（不会删除 Agent）：

```bash
curl -fsSL https://raw.githubusercontent.com/jwjccc/chicken-dashboard/main/scripts/uninstall-panel.sh -o uninstall-panel.sh && chmod +x uninstall-panel.sh && sudo ./uninstall-panel.sh
```

目录
```bash
cd server-probe-monitor
node hub/server.js
```

登录方式

```text
http://本机ip:8080
```
