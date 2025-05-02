# Upack

Реализация алгоритма PolyUnpack на python

# Установка

```
pip install -r requirements.txt
```

# Переенные среды

SAMPLE_PATH - путь до папки с сэмлами
DUMP_PATH - путь до папки с дампами
PD_PATH - путь до pd64.exe

# Использование 

```
usage: main.py [-h] [--all | --no-all] [--pd | --no-pd] [--dump | --no-dump] sample

positional arguments:
  sample             Sample name

options:
  -h, --help         show this help message and exit
  --all, --no-all    Print all instructions
  --pd, --no-pd      Enable memroy pd64 dump
  --dump, --no-dump  Enable binary dump
```