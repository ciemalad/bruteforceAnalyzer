# from tkinter import *
# import customtkinter
#
# customtkinter.set_default_color_theme("dark-blue")
# # Tworzenie głównego okna aplikacji
# root = customtkinter.CTk()
# root.title("Moja aplikacja")
# root.geometry("400x300")
#
# myButton=Button(root,text="Hello World!",font=("Inter",14))
# myButton.place(relx=0.5,rely=0.5,anchor=CENTER)
#
# # Rozpoczęcie pętli głównej aplikacji
# root.mainloop()

import win32evtlog
import platform
import datetime

def win_readLogs():

    channelName = "Security"
    flags = win32evtlog.EvtQueryReverseDirection
    evtQueryResultNo = 100 #co tutaj i jak dodobić czasowe żeby sprawdzać co jakiś czas
    evtQuery = "*[System[(EventID=4624 or EventID=4625)]]"
    evtQueryTimeout = -1

    evtQueryResult = win32evtlog.EvtQuery(channelName, flags, evtQuery, None)

    events = win32evtlog.EvtNext(evtQueryResult, evtQueryResultNo, evtQueryTimeout, 0)
    for event in events:
        print(win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml))

def lnx_readLogs():
    x=1
def rule ():
    return 1;

lastChecked=0
if(platform.system()=="Windows"):
    print("Windows")
    win_readLogs()
elif(platform.system()=="Linux"):
    print("Linux")
    lnx_readLogs()
