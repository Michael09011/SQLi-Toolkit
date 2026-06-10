# SQLi Toolkit

간단한 SQL 인젝션 테스트 및 분석을 위한 데스크탑 도구입니다.

## 설명

이 저장소는 Windows용으로 패키징된 SQLi Toolkit 애플리케이션을 포함합니다. GUI 기반 실행 파일과 설치 프로그램을 생성하는 스크립트가 포함되어 있습니다.

## 필요 조건

- Python 3.8 이상
- pip

필요한 Python 패키지는 `requirements.txt`에서 확인하고 설치할 수 있습니다.

## 설치

```powershell
python -m pip install -r requirements.txt
```

## 실행

개발 중에는 다음 명령으로 애플리케이션을 실행합니다:

```powershell
python sqli_toolkit_qt.py
```

## 배포 / 설치 프로그램 생성

Windows 설치 프로그램은 저장소에 포함된 스크립트와 설정 파일을 사용하여 만들 수 있습니다.

- NSIS 설정: `installer.nsi`
- 빌드 스크립트(Windows PowerShell): `build_installer.ps1`

PowerShell에서 빌드 스크립트를 실행하여 설치 프로그램을 생성합니다:

```powershell
.\build_installer.ps1
```

또는 PyInstaller를 직접 사용하여 exe를 빌드하려면 프로젝트에 포함된 `.spec` 파일을 참조하세요 (`SQLiToolkit.spec`).

## 개발

개발용 의존성은 `requirements-dev.txt`에 정리되어 있습니다. 테스트나 린트 도구를 추가하려면 해당 파일을 확인하세요.

## 파일 요약

- `sqli_toolkit_qt.py` - 애플리케이션 메인 스크립트
- `build_installer.ps1` - Windows 설치 프로그램을 생성하는 PowerShell 스크립트
- `installer.nsi` - NSIS 설치 스크립트
- `requirements.txt` / `requirements-dev.txt` - 의존성

## 기여

이 프로젝트에 기여하려면 이슈를 열거나 풀 리퀘스트를 보내주세요.

## 라이선스

라이선스는 아직 명시되어 있지 않습니다. 적절한 라이선스를 추가하세요.
