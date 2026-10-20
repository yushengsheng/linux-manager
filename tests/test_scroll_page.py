import tkinter as tk
from tkinter import ttk
import unittest

from linux_manager.widgets import ScrollPage


class ScrollPageWheelTests(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.root.title("滚动区域回归测试")
        self.root.geometry("640x400")
        self.addCleanup(self.root.destroy)
        self.page = ScrollPage(self.root, "white")
        self.page.pack(fill="both", expand=True)

    def finish_layout(self, parent=None):
        ttk.Frame(parent or self.page.content, height=1200).pack(fill="x")
        self.root.update()

    def wheel(self, widget, delta=-120):
        widget.event_generate("<MouseWheel>", delta=delta, x=5, y=5)
        self.root.update()

    def tree(self, count=100):
        tree = ttk.Treeview(self.page.content, height=5)
        tree.pack(fill="x")
        for index in range(count):
            tree.insert("", "end", text=f"项目 {index}")
        return tree

    def assert_native_scroll_only(self, widget):
        # Compare with Tk's own handling to catch both lost and doubled scrolls.
        for delta in (-120, 120, -1, 1):
            with self.subTest(widget=widget.winfo_class(), delta=delta):
                tags = widget.bindtags()
                widget.yview_moveto(0.5)
                widget.bindtags(tuple(tag for tag in tags if tag != "all"))
                self.wheel(widget, delta)
                expected = widget.yview()
                widget.bindtags(tags)
                widget.yview_moveto(0.5)
                self.page.canvas.yview_moveto(0.25)
                before = self.page.canvas.yview()
                self.wheel(widget, delta)
                self.assertEqual(widget.yview(), expected)
                self.assertEqual(self.page.canvas.yview(), before)

    def test_project_table_keeps_native_scroll_without_moving_page(self):
        tree = self.tree()
        self.finish_layout()
        tree.yview_moveto(0)
        self.wheel(tree)
        self.assertGreater(tree.yview()[0], 0)
        self.assert_native_scroll_only(tree)

    def test_text_details_and_readonly_logs_scroll_independently(self):
        text = tk.Text(self.page.content, height=5)
        text.pack(fill="x")
        text.insert("end", "".join(f"日志 {index}\n" for index in range(100)))
        self.finish_layout()
        for state in ("normal", "disabled"):
            with self.subTest(state=state):
                text.configure(state=state)
                self.assert_native_scroll_only(text)

    def test_listbox_scrolls_independently(self):
        listing = tk.Listbox(self.page.content, height=5)
        listing.pack(fill="x")
        listing.insert("end", *(f"项目 {index}" for index in range(100)))
        self.finish_layout()
        self.assert_native_scroll_only(listing)

    def test_table_edges_and_short_or_empty_tables_do_not_move_page(self):
        tree = self.tree()
        self.finish_layout()
        for count in (100, 1, 0):
            if count < 100:
                tree.delete(*tree.get_children())
                for index in range(count):
                    tree.insert("", "end", text=str(index))
            for position, delta in ((0, 120), (1, -120)):
                with self.subTest(rows=count, position=position):
                    tree.yview_moveto(position)
                    self.page.canvas.yview_moveto(0.25)
                    before = self.page.canvas.yview()
                    self.wheel(tree, delta)
                    self.assertEqual(self.page.canvas.yview(), before)

    def test_page_controls_and_background_scroll_the_page(self):
        label = ttk.Label(self.page.content, text="项目信息区域外")
        label.pack()
        button = ttk.Button(self.page.content, text="刷新")
        button.pack()
        entry = ttk.Entry(self.page.content)
        entry.pack()
        self.finish_layout()
        for widget in (label, button, entry, self.page.content, self.page.canvas):
            with self.subTest(widget=widget.winfo_class()):
                self.page.canvas.yview_moveto(0)
                self.wheel(widget)
                self.assertGreater(self.page.canvas.yview()[0], 0)

    def test_nested_pages_scroll_only_the_nearest_page(self):
        nested = ScrollPage(self.page.content, "white")
        nested.configure(height=180)
        nested.pack(fill="x")
        nested.pack_propagate(False)
        label = ttk.Label(nested.content, text="内层页面")
        label.pack()
        self.finish_layout(nested.content)
        self.finish_layout()
        outer_before = self.page.canvas.yview()
        self.wheel(label)
        self.assertGreater(nested.canvas.yview()[0], 0)
        self.assertEqual(self.page.canvas.yview(), outer_before)

    def test_switching_pages_and_destroying_a_page_preserves_routing(self):
        old_label = ttk.Label(self.page.content, text="旧页面")
        old_label.pack()
        self.finish_layout()
        self.page.pack_forget()
        second = ScrollPage(self.root, "white")
        second.pack(fill="both", expand=True)
        label = ttk.Label(second.content, text="新页面")
        label.pack()
        self.finish_layout(second.content)
        self.page.destroy()
        self.wheel(label)
        self.assertGreater(second.canvas.yview()[0], 0)

    def test_widget_path_prefix_does_not_route_to_sibling_page(self):
        second = ScrollPage(self.root, "white")
        second.pack(fill="both", expand=True)
        label = ttk.Label(second.content, text="第二个页面")
        label.pack()
        self.finish_layout(second.content)
        self.finish_layout()
        before = self.page.canvas.yview()
        self.wheel(label)
        self.assertGreater(second.canvas.yview()[0], 0)
        self.assertEqual(self.page.canvas.yview(), before)


if __name__ == "__main__":
    unittest.main()
