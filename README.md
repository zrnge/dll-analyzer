# DLL Analyzer

A handy Python tool for dynamic analysis of DLL exports.  
### It lets you:
- List all exported functions from a DLL
- Define argument and return types manually
- Call functions with your own parameters
- Use from the terminal with arguments

**⚠️ Warning:** Running suspicious DLLs can be dangerous.
Always test inside a VM or sandbox.

---

## 🔧 Installation
```bash
git clone https://github.com/zrnge/dll-analyzer.git
cd dll-analyzer
pip install -r requirements.txt
```
### Usage
```bash
dll_analyzer.py [-h] [--list] [--call FUNC] [--args [ARGS ...]] [--types [TYPES ...]] [--restype RESTYPE] dll
```


### options:
``
  -h, --help           show this help message and exit
  --list               List exported functions
  --call FUNC          Function name to call
  --args [ARGS ...]    Arguments for function
  --types [TYPES ...]  Argument types (int, str)
  --restype RESTYPE    Return type (int, str, void)
  ``
