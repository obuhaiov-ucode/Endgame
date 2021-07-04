# Endgame HTML requests parser

## DESCRIPTION:

API allows to work with html requests GET, POST, PUT, PATCH, DELETE and visualize the data of the request and response in few convenient formats.

## PREREQUISITES:

The following programs and add-ons are required for use:

Installed Python 3 (on UNIX systems and macOS is installed by default):
To install in WINDOWS:
```python
https://www.python.org/downloads/windows/ - the official site where you can download.
```
For UNIX systems and macOS: Open a terminal and enter python3. Most likely, you will be kindly greeted by python 3:

→ Python 3.6.9 (default, Jan 26 2021, 15:33:00) [GCC 8.4.0] on linux Type "help", "copyright", "credits" or "license" for more information.

If so, you can be congratulated: you already have python 3.

Otherwise you need to install the * python3 * package:
```python
sudo apt-get install python3
```
Tkinter:

Installation
```python
pip install tkinter
```

YAML extension:

```python
$ pip install pyyaml
```

# Usage:

```python
python3 endgame.py [-g, --gui]

Program operation through the console:

```python
python3 endgame.py [-h, --help] 

To display a help list.

optional arguments:
-h, --help
    Show this help message and exit

-g, --gui
    Activate GUI mode

--history {show,clear}
    Show 10 last requests or clear all

-a AUTH AUTH, --auth AUTH AUTH
    Set username and password

-l {debug,info,warning}, --log {debug,info,warning}
    Set logging level

  -m {GET,POST,PUT,PATCH,DELETE}, --method 
{GET,POST,PUT,PATCH,DELETE}
    Set request method

-e ENDPOINT, --endpoint ENDPOINT
    Set endpoint of request

-p PARAMS [PARAMS ...], --params PARAMS [PARAMS ...]
    Set params of request

--headers HEADERS [HEADERS ...]
    Set headers of request

-b BODY [BODY ...], --body BODY [BODY ...]
    Set body of request
--tree
    Set Tree view mode
-r, --raw
    Set Raw view mode
--pretty
    Set Pretty view mode
-y, --yaml
    Set Yaml view mode

Authors: 
Oleksii Buhaiov - obuhaiov@student.ucode.world 
Myroslava Tararuieva - mtararuiev@student.ucode.world 
Yura Vel - yvel@student.ucode.world 
Ivan Ivanych - iivanych@student.ucode.world

