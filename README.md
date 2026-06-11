# ⚡ SQLi Toolkit

SQL Injection 테스트 및 분석을 위한 PyQt6 기반 데스크탑 툴

---

## 기능

| 탭 | 기능 |
|---|---|
| ⚡ sqlmap | DB → 테이블 → 컬럼 → 덤프 단계별 자동화 |
| 🕵 Blind SQLi | Boolean-based / Time-based 수동 추출 |
| 🔍 취약점 스캐너 | SQLi / XSS / Directory Traversal / 정보 노출 자동 탐지 |

### 주요 기능
- 파라미터 자동 탐지 (GET / POST 폼 크롤링)
- 컬럼 체크박스 복수 선택 → `-C` 자동 생성
- 덤프 결과 데이터 뷰 + CSV 저장
- 옵션 저장 / 불러오기 (JSON)

---

## 요구사항

- Python 3.8 이상
- sqlmap

```bash
pip install PyQt6 requests beautifulsoup4
pip install sqlmap
```

---

## 실행

```bash
python3 sqli_toolkit_qt.py
```

---

## Windows 빌드

```powershell
pip install pyinstaller
pyinstaller --onefile --windowed --name "SQLiToolkit" sqli_toolkit_qt.py
```

`dist/SQLiToolkit.exe` 생성됨

---

## 파일 구조

```
sqli_toolkit_qt.py     메인 스크립트
requirements.txt       의존성 목록
README.md              이 파일
```

---

## 주의사항

> 허가 없는 시스템에 대한 취약점 테스트는 불법입니다

---

**by Michael**
