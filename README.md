# Cyberattack Detection

A small desktop application that checks a server log file and reports suspicious IP addresses.

Course project for **Analysis of Algorithms**, SMI University, Karachi.

## Project structure

```
cyberattack-detection/
├── data/            sample log file and blacklist
├── tests/           test files for the threshold limits
├── merge_sort.py    Merge Sort
├── binary_search.py Binary Search
├── detector.py      reads the log, counts, applies the rules
└── app.py           desktop window (Tkinter)
```

## Build the .exe (Windows)

Install PyInstaller once:

```
pip install pyinstaller
```

Build from the project folder:

```
pyinstaller --onefile --windowed --name CyberattackDetection app.py
```

The file `CyberattackDetection.exe` is created in the `dist` folder.
Copy `data/blacklist.csv` into the same folder as the .exe, because the
program looks for `blacklist.csv` next to itself.
