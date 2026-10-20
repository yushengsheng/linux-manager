"""Page layout and presentation; actions use the shared App controller."""
import tkinter as tk
from tkinter import ttk

from .gui_common import INK
from .widgets import sync_tree


class HistoryPage:
    def _history_page(self):
        page = self.pages["操作记录"].content
        self._description(page, "进度、结果与恢复记录", "后台任务在服务器执行。重新连接后可以刷新记录，查看上次任务的结果；断线时请勿重复部署。")
        row = ttk.Frame(page); row.pack(fill="x", pady=(0, 12))
        self._button(row, "刷新记录", self._tasks).pack(side="left")
        self._button(row, "查看任务详情", self._task_detail).pack(side="left", padx=10)
        self._button(row, "恢复待验证变更", self._recover).pack(side="left")
        self._button(row, "查看本次新密码", self._task_password).pack(side="left", padx=10)
        self.task_tree = self._tree(page, [("id", "任务编号", 235), ("operation", "操作", 145), ("state", "状态", 160), ("message", "结果", 440)], height=7)
        self.task_text = tk.Text(page, height=9, wrap="word", bg="white", foreground=INK, font="TkDefaultFont", relief="flat", padx=14, pady=14, state="disabled")
        self.task_text.pack(fill="both", expand=True, pady=(15, 0))

    def _show_tasks(self, tasks):
        seen = set(); self.latest_tasks = []
        rows = []
        for task in tasks:
            if task["id"] in seen: continue
            seen.add(task["id"]); self.latest_tasks.append(task)
            names = {"deploy": "服务部署", "uninstall": "项目卸载（保留数据）", "create_admin": "创建管理员", "rename_user": "账号改名", "password": "修改密码", "ssh": "SSH 设置", "firewall": "防火墙", "updates": "安全更新", "backup": "配置备份", "restore": "配置恢复", "service": "服务管理", "account_access": "账号登录限制", "delete_user": "删除用户并保留文件", "ssh_hardening": "SSH 连接防护", "fail2ban": "防猜密码保护"}
            names.update(prepare_key="安装并验证加密密钥", login_policy="仅密钥登录策略", retire_key="撤销原档案旧钥匙")
            states = {"queued": "排队中", "running": "执行中", "awaiting_verification": "等待连接验证", "succeeded": "已完成", "failed": "未完成", "rolled_back": "已恢复原配置", "recovery_failed": "恢复未完成，需处理", "submission_unknown": "提交未确认"}
            rows.append((task["id"], (task["id"], names.get(task["operation"], task["operation"]), states.get(task["state"], task["state"]), self._redactor().text(task["message"]))))
        sync_tree(self.task_tree, rows)

    def _task_detail(self):
        selected = self.task_tree.selection()
        if not selected: return
        task = next(t for t in self.latest_tasks if t["id"] == selected[0])
        text = "\n".join(event["message"] for event in task.get("events", []))
        text += "\n\n" + task["message"]
        if task.get("diagnostic"): text += "\n" + task["diagnostic"]
        self._replace_text(self.task_text, self._redactor().text(text))
