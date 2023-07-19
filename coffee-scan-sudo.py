import tkinter as tk
from tkinter import messagebox, scrolledtext
from subprocess import Popen, PIPE
import os
import threading
import re

class Application(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.master.title("Coffee Scan ~ c3Nz")  # Set the window title
        self.master.geometry("210x160")  # Set the window size to be 810x610
        self.pack()
        self.create_widgets()

    def create_widgets(self):
        self.ip_label = tk.Label(self)
        self.ip_label["text"] = "Enter IP:"
        self.ip_label.pack(side="top")

        self.ip_entry = tk.Entry(self)
        self.ip_entry.pack(side="top")

        self.nmap_var = tk.IntVar()
        self.nmap_check = tk.Checkbutton(self, text="Run nmap", variable=self.nmap_var)
        self.nmap_check.pack(side="top")

        self.versions_var = tk.IntVar()
        self.versions_check = tk.Checkbutton(self, text="Run versions scan", variable=self.versions_var)
        self.versions_check.pack(side="top")

        self.whatweb_var = tk.IntVar()
        self.whatweb_check = tk.Checkbutton(self, text="Run whatweb", variable=self.whatweb_var)
        self.whatweb_check.pack(side="top")

        self.scan_button = tk.Button(self)
        self.scan_button["text"] = "SCAN"
        self.scan_button["command"] = self.run_scan
        self.scan_button.pack(side="top")

    def run_scan(self):
        self.ip = self.ip_entry.get()
        if not self.ip:
            messagebox.showerror("Error", "IP cannot be empty")
            return

        self.output_window = tk.Toplevel(self)
        self.output_window.title("Scan Output")

        self.nmap_output = scrolledtext.ScrolledText(self.output_window, width=50, height=10)
        self.nmap_output.pack(side="top", fill="both", expand=True)

        self.versions_output = scrolledtext.ScrolledText(self.output_window, width=50, height=10)
        self.versions_output.pack(side="top", fill="both", expand=True)

        self.whatweb_output = scrolledtext.ScrolledText(self.output_window, width=50, height=10)
        self.whatweb_output.pack(side="top", fill="both", expand=True)

        if self.nmap_var.get():
            threading.Thread(target=self.run_command, args=(["sudo", "nmap", "-sS", "--min-rate", "5000", self.ip], f"port-scan-{self.ip}", self.nmap_output, self.versions_var.get())).start()

        if self.whatweb_var.get():
            threading.Thread(target=self.run_command, args=(["whatweb", self.ip], f"whatweb-{self.ip}", self.whatweb_output, False)).start()

    def run_command(self, command, filename, output_field, run_versions_scan=False):
        process = Popen(command, stdout=PIPE)
        output, _ = process.communicate()

        # Decodifica la salida del comando y elimina los códigos de escape ANSI
        output_text = output.decode()
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        output_text = ansi_escape.sub('', output_text)

        # Asegúrate de que el directorio ~/autoscan exista, si no, créalo
        if not os.path.exists(os.path.expanduser('~/autoscan')):
            os.makedirs(os.path.expanduser('~/autoscan'))

        # Asegúrate de que el archivo exista, si no, créalo
        if not os.path.isfile(os.path.expanduser(f"~/autoscan/{filename}")):
            with open(os.path.expanduser(f"~/autoscan/{filename}"), 'w') as f:
                pass

        with open(os.path.expanduser(f"~/autoscan/{filename}"), "w") as f:
            f.write(output_text)

        output_field.insert('end', output_text)
        self.master.after_idle(lambda: messagebox.showinfo("Info", f"{command[0]} completed"))

        # Si el checkbox de versions scan está seleccionado, ejecuta el versions scan
        # después de que el primer nmap scan haya terminado
        if run_versions_scan and self.versions_var.get():
            self.run_versions_scan(output_text)

    def run_versions_scan(self, nmap_output):
        # Busca los puertos abiertos en la salida del comando nmap
        open_ports = re.findall(r'(\d+)/tcp open', nmap_output)
        if open_ports:
            ports = ",".join(open_ports)
            self.run_command(["sudo", "nmap", "-sCV", "-p" + ports, self.ip], f"versions-{self.ip}", self.versions_output, False)

root = tk.Tk()
app = Application(master=root)
app.mainloop()
