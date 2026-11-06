
## 小鸡探针面板

快速安装

```bash
curl -L https://raw.githubusercontent.com/jwjccc/chicken-dashboard/main/scripts/install-panel.sh -o install-panel.sh && chmod +x install-panel.sh && env PROBE_REPO_URL=https://github.com/jwjccc/chicken-dashboard.git PROBE_REF=main PROBE_PORT=8080 ./install-panel.sh

```
Node.js升级（需要22+）
```bash
apt-get update && apt-get install -y ca-certificates curl gnupg

curl -fsSL https://deb.nodesource.com/setup_22.x | bash -

apt-get install -y nodejs

node --version
```
卸载面板（不会删除 Agent）：
```bash
curl -fsSL https://raw.githubusercontent.com/jwjccc/chicken-dashboard/main/scripts/uninstall-panel.sh -o uninstall-panel.sh && chmod +x uninstall-panel.sh && sudo ./uninstall-panel.sh
```

登录

```text
http://本机ip:8080
```

