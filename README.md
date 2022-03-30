# mbra-generator

- [mbra-generator](#mbra-generator)
  - [Quick Start](#quick-start)

## Quick Start

```bash
python3 -m venv venv
source ./venv/bin/activate
pip install -r requirements.txt
python ./src/csv_to_mbra/csv_to_mbra_xml.py
diff <(xmllint --c14n ./src/test/mbra.xml) <(xmllint --c14n ./src/outputs/mbra.xml)
```

```powershell
python -m venv venv
.\venv\Scripts\activate.ps1
pip install -r requirements.txt
python ./src/csv_to_mbra/csv_to_mbra_xml.py
```
