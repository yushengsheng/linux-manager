"""Formatting and login-record dialog for the existing management page."""
import tkinter as tk
from tkinter import ttk

from .project_info import server_key

KINDS = {"systemd": "系统服务", "systemd-user": "用户服务", "docker": "Docker 容器",
         "pm2": "PM2 应用", "process": "独立进程", "directory": "安装目录"}
STATES = {"active": "运行中", "running": "运行中", "inactive": "已停止", "exited": "已停止",
          "failed": "运行失败", "dead": "已停止", "created": "未启动", "paused": "已暂停",
          "restarting": "重启中", "registered": "已登记", "detected": "已发现安装", "unknown": "未知"}


def information_rows(information, connection):
    project = information["project"]
    rows = [("项目名称", project["name"]), ("类型", KINDS.get(project["kind"], project["kind"])),
            ("项目状态", STATES.get(project["state"], project["state"])), ("服务器", connection.label)]
    for key, label in (("product", "识别软件"), ("version", "安装版本"), ("revision", "安装修订"), ("startup", "自启 / 保存状态"),
                       ("unit", "服务名称"), ("description", "项目描述"), ("executable", "运行程序"),
                       ("working_directory", "安装 / 工作目录"), ("definition", "服务定义"),
                       ("image", "容器镜像"), ("compose_project", "Compose 项目"), ("discovery_note", "识别说明")):
        if project.get(key): rows.append((label, str(project[key])))
    for port in project.get("ports", []):
        text = str(port["port"]) + " / " + port["protocol"].upper() + ("（仅本机）" if port["local_only"] else "（对外监听）")
        if port.get("container_port"): text += " → 容器端口 " + str(port["container_port"])
        rows.append(("监听端口", text))
    for endpoint in project.get("web_endpoints", []):
        if not endpoint.get("url"): continue
        rows.append(("服务器本机网址" if endpoint.get("local_only") else "项目管理网址", endpoint["url"]))
        rows.append(("网址识别依据", endpoint.get("source", "")))
    if project.get("web_note"): rows.append(("访问说明", project["web_note"]))
    for key, label in (("url", "项目管理网址"), ("username", "登录账号（本机记录）"),
                       ("password", "登录密码（本机记录）"), ("notes", "本机备注")):
        if information.get("credentials", {}).get(key): rows.append((label, information["credentials"][key]))
    if information.get("credentials_warning"): rows.append(("本机登录记录", information["credentials_warning"]))
    if information.get("cache_warning"): rows.append(("本机保存", information["cache_warning"]))
    if information.get("saved_at"):
        rows.extend([("保存时间", information["saved_at"]), ("信息来源", "本机保存的上次读取结果；刷新可更新状态。")])
    return rows


def credentials_dialog(app, connection, information, saved):
    identifier = information["project"]["id"]
    dialog = tk.Toplevel(app); dialog.title("项目登录信息 · 仅保存在本机"); dialog.transient(app)
    body = ttk.Frame(dialog, padding=18); body.pack(fill="both", expand=True)
    ttk.Label(body, text="此处只更新本机钥匙串记录。实际修改账号密码，请进入项目原有后台。", wraplength=500).pack(anchor="w")
    variables = {}
    for key, label in (("url", "项目管理网址"), ("username", "登录账号"), ("password", "登录密码"), ("notes", "备注")):
        ttk.Label(body, text=label).pack(anchor="w", pady=(10, 3))
        variable = tk.StringVar(dialog, value=information.get("credentials", {}).get(key, "")); variables[key] = variable
        ttk.Entry(body, textvariable=variable, show="•" if key == "password" or app.privacy.get() else "", width=54).pack(fill="x")
    def save():
        if app.busy: return
        if not app.current or server_key(app.current) != server_key(connection):
            app.status.configure(text="服务器已切换，请关闭后重新补充登录信息。")
            return
        values = {key: variable.get() for key, variable in variables.items()}
        def done(values):
            if dialog.winfo_exists(): dialog.destroy()
            saved(values)
        app._run(lambda: app.controller.save_external_project_credentials(connection, identifier, values), done, "保存项目登录信息到本机钥匙串…")
    app._button(body, "保存本机记录", save, track=False).pack(anchor="w", pady=(12, 0))
    return dialog
