from tkinter import ttk
import tkinter as tk


def install_check_style(style, root):
    """Keep native keyboard/variable handling, replace the clam X indicator."""
    def icon(selected, disabled=False):
        picture = tk.PhotoImage(master=root, width=20, height=20)
        border = "#c5cedb" if not selected else "#91d5ad"
        fill = "#ffffff" if not selected else "#ebfaf1"
        tick = "#90b59d" if disabled else "#16a34a"
        for y in range(20):
            for x in range(20):
                if x < 1 or y < 1 or x > 18 or y > 18:
                    continue
                if (x < 4 or x > 15) and (y < 4 or y > 15):
                    cx, cy = (4 if x < 4 else 15), (4 if y < 4 else 15)
                    if (x - cx) ** 2 + (y - cy) ** 2 > 10:
                        continue
                color = border if x in {1, 18} or y in {1, 18} else fill
                if selected:
                    for ax, ay, bx, by in [(5, 10, 8, 13), (8, 13, 15, 6)]:
                        t = max(0, min(1, ((x-ax)*(bx-ax)+(y-ay)*(by-ay))/((bx-ax)**2+(by-ay)**2)))
                        if (x-ax-t*(bx-ax))**2+(y-ay-t*(by-ay))**2 <= 1.5:
                            color = tick
                picture.put(color, (x, y))
        return picture
    root._check_images = [icon(False), icon(True), icon(False, True), icon(True, True)]
    off, on, off_disabled, on_disabled = root._check_images
    style.element_create("GreenCheck.indicator", "image", off, ("disabled", "selected", on_disabled), ("disabled", off_disabled), ("selected", on), width=20, sticky="w")
    def replace(layout):
        result = []
        for name, options in layout:
            values = dict(options)
            if "children" in values: values["children"] = replace(values["children"])
            result.append(("GreenCheck.indicator" if name == "Checkbutton.indicator" else name, values))
        return result
    style.layout("TCheckbutton", replace(style.layout("TCheckbutton")))


def sync_tree(tree, rows):
    """Update changed cells without destroying selection or scroll position."""
    identifiers = {identifier for identifier, _ in rows}
    existing = set(tree.get_children())
    removed = existing - identifiers
    if removed: tree.delete(*removed)
    order = list(tree.get_children())
    for index, (identifier, values) in enumerate(rows):
        values = tuple(str(value) for value in values)
        if identifier not in existing:
            tree.insert("", index, iid=identifier, values=values)
            order.insert(index, identifier)
        else:
            if tuple(tree.item(identifier, "values")) != values:
                tree.item(identifier, values=values)
            if index >= len(order) or order[index] != identifier:
                tree.move(identifier, "", index)
                order.remove(identifier); order.insert(index, identifier)


class HelpAction(ttk.Frame):
    def __init__(self, parent, text, action, help_action, style="TButton"):
        super().__init__(parent)
        self.button = ttk.Button(self, text=text, command=action, style=style)
        self.button.pack(side="left")
        ttk.Button(self, text="？", command=help_action, width=2, style="Help.TButton").pack(side="left", padx=(2, 0))

    def configure(self, cnf=None, **kwargs):
        if "state" in kwargs:
            self.button.configure(state=kwargs.pop("state"))
        if cnf or kwargs:
            return super().configure(cnf, **kwargs)


class ScrollPage(ttk.Frame):
    def __init__(self, parent, background):
        super().__init__(parent)
        self.canvas = tk.Canvas(self, bg=background, highlightthickness=0, borderwidth=0, yscrollincrement=14)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.content = ttk.Frame(self.canvas, padding=16)
        self.item = self.canvas.create_window((0, 0), window=self.content, anchor="nw")
        self._region_job = None
        self._width = None
        self._region = None
        self._wrap_lengths = {}
        self.content.bind("<Configure>", self._schedule_region)
        self.canvas.bind("<Configure>", self._resize)
        self.bind("<Map>", self._schedule_region)
        root = self.winfo_toplevel()
        if not hasattr(root, "_scroll_pages"):
            root._scroll_pages = []
            def wheel(event):
                widget = event.widget
                while isinstance(widget, tk.Misc):
                    if isinstance(widget, ScrollPage):
                        if not widget.winfo_ismapped():
                            return
                        delta = event.delta
                        units = -int(delta / 120) * 3 if abs(delta) >= 120 else -delta
                        if units: widget.canvas.yview_scroll(units, "units")
                        return "break"
                    # Native tables, text boxes and other scrollable children
                    # already handled the wheel in their class binding. Keep
                    # ownership even at an edge; never also move the page.
                    page_canvas = isinstance(widget.master, ScrollPage) and widget is widget.master.canvas
                    if callable(getattr(widget, "yview", None)) and not page_canvas:
                        return
                    widget = widget.master
            root.bind_all("<MouseWheel>", wheel, add="+")
        root._scroll_pages.append(self)

    def _resize(self, event):
        if event.width != self._width:
            self._width = event.width
            self.canvas.itemconfigure(self.item, width=event.width)
            self._schedule_region()

    def _schedule_region(self, event=None):
        if self._region_job is None and self.winfo_ismapped():
            self._region_job = self.after_idle(self._refresh_region)

    def _refresh_region(self):
        self._region_job = None
        if not self.winfo_ismapped(): return
        width = self._width or self.canvas.winfo_width()
        def wrap(parent):
            for child in parent.winfo_children():
                if not child.winfo_ismapped():
                    continue
                if isinstance(child, ttk.Label):
                    length = child.winfo_pixels(child.cget("wraplength") or 0)
                    if length > 0:
                        original = self._wrap_lengths.setdefault(child, length)
                        available = max(120, width - 16 - (child.winfo_rootx() - self.content.winfo_rootx()))
                        desired = min(original, available)
                        if length != desired:
                            child.configure(wraplength=desired)
                wrap(child)
        wrap(self.content)
        region = (0, 0, width, self.content.winfo_reqheight())
        if region != self._region:
            self._region = region
            self.canvas.configure(scrollregion=region)
