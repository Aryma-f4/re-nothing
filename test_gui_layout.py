"""GUI smoke checks on desktop runners."""
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("FLAGR_HOME", tempfile.mkdtemp(prefix="flagr-gui-test-"))
import flagr


@unittest.skipUnless(sys.platform == "darwin" or os.name == "nt", "desktop display required")
class GuiLayoutTest(unittest.TestCase):
    def test_main_tabs_remain_visible_above_activity(self):
        import tkinter as tk
        from tkinter import ttk

        cfg = flagr.load_cfg()
        cfg["geometry"] = "900x680"
        flagr.save_cfg(cfg)
        observed = {}
        original_mainloop = tk.Tk.mainloop

        def inspect(root):
            root.after(350, root.quit)
            original_mainloop(root)

            def descendants(widget):
                for child in widget.winfo_children():
                    yield child
                    yield from descendants(child)

            tabs = [w for w in descendants(root) if isinstance(w, ttk.Notebook)
                    and "Submit" in [w.tab(i, "text") for i in w.tabs()]]
            self.assertEqual(len(tabs), 1)
            panes = [w for w in descendants(root) if isinstance(w, ttk.Panedwindow)]
            if panes:
                panes[0].sashpos(0, 1)
                root.update_idletasks()
            observed["height"] = tabs[0].winfo_height()
            observed["viewable"] = tabs[0].winfo_viewable()
            observed["root_height"] = root.winfo_height()
            root.destroy()

        with patch.object(tk.Tk, "mainloop", inspect):
            flagr.run_gui()
        self.assertGreaterEqual(observed["height"], 300, str(observed))


if __name__ == "__main__":
    unittest.main()
