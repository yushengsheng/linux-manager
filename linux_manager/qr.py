"""Encode node links locally; never send credentials to a QR service."""
import io

from .models import ManagerError


def is_node_link(value):
    return isinstance(value, str) and value.startswith(("hysteria2://", "hy2://", "vless://"))


def qr_png(value, maximum=380):
    if not is_node_link(value) or len(value.encode()) > 4096:
        raise ManagerError("请选择有效的 HY2 或 VLESS 节点链接。")
    try:
        import segno
    except ImportError:
        raise ManagerError("二维码组件未安装；源码运行请先安装 requirements.txt，独立安装包已自带。") from None
    try:
        code = segno.make(value, error="m", micro=False, encoding="utf-8")
        scale = max(1, maximum // code.symbol_size(scale=1, border=4)[0])
        stream = io.BytesIO()
        code.save(stream, kind="png", scale=scale, border=4, dark="black", light="white")
        return stream.getvalue()
    except (ValueError, segno.DataOverflowError):
        raise ManagerError("节点链接过长，无法展示二维码；请使用复制链接导入。") from None
