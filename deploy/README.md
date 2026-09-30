# 可选的外部定时执行模板

CPR 3.18 + 插件 v0.2.0 优先使用配置 `auto_probe: true`，由宿主维护周期触发，无需 SSH 定时任务。只有自动模式20秒期限不足时再使用此模板；使用前设 `auto_probe: false`，避免重复调度。

这里交付 systemd 模板，不会自动安装或启用服务。安装插件后，将 `quality-guard.env.example` 复制为 `/etc/codex-quality-guard.env`，填写实际二进制路径、网关工作目录和插件实例 UUID。实例 UUID 与 `jiahao6635.quality-guard` 插件 ID 是不同标识。

将本项目放到 `/opt/codex-quality-guard`，或修改 service 的 `ExecStart`。将 service 的 `User`、`Group` 改为网关实际身份，复用网关的环境文件、数据库、Redis、加密配置和数据目录。若网关运行在容器中，需要按实际容器部署方式适配执行命令；本模板针对直接运行宿主二进制的部署。

先手动执行一次 `scripts/tick.sh`，再复制两个 unit 文件到 `/etc/systemd/system/`，执行：

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now codex-quality-guard.timer
sudo systemctl status codex-quality-guard.timer
sudo journalctl -u codex-quality-guard.service -n 50
```

timer 在上次执行结束后等待 30 秒再触发。`flock` 防止本机重叠执行，跨节点并发由插件状态 CAS/租约保护。宿主的插件命令总期限为 120 秒；service 的 180 秒是包含宿主启动与退出的外层限制，不能延长模型调用期限。

停止探针：`sudo systemctl disable --now codex-quality-guard.timer`。停止 timer 不会恢复已隔离账号；恢复需要符合插件规则或由管理员显式处理。组成员变更通过宿主配置通知传播，不能撤销已经开始的业务请求。
