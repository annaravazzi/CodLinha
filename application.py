import tkinter as tk
from tkinter import messagebox, scrolledtext
from host import *
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from encode_decode import *

KEY = 14

# Interface gráfica
class Application:
    def __init__(self, root):
        self.host = Host()
        self.encode_decode = EncodeDecode(generate_alphabet(), KEY)

        self.root = root
        self.root.title("Codificação AMI Pseudoternário")

        self.receive_toggle = tk.BooleanVar()
        self.receive_toggle.set(False)

        # Frame de conexão
        self.conn_frame = tk.Frame(root)
        self.create_conn_toggle = tk.BooleanVar()
        self.create_conn_checkbutton = tk.Checkbutton(self.conn_frame)
        self.confirm_button = tk.Button(self.conn_frame)
        self.ip = tk.StringVar()
        self.port = tk.StringVar()
        self.ip_entry = tk.Entry(self.conn_frame)
        self.port_entry = tk.Entry(self.conn_frame)

        self.init_conn_frame()
        self.canvas = None  # To store the graph canvas

        # Create the canvas and scrollbar
        self.scroll_canvas = tk.Canvas(root)
        self.scrollbar = tk.Scrollbar(root, orient="vertical", command=self.scroll_canvas.yview)
        self.scroll_canvas.configure(yscrollcommand=self.scrollbar.set)
        
        self.scrollbar.pack(side="right", fill="y")
        self.scroll_canvas.pack(side="left", fill="both", expand=True)

        # Create a frame inside the canvas
        self.scrollable_frame = tk.Frame(self.scroll_canvas)
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.scroll_canvas.configure(
                scrollregion=self.scroll_canvas.bbox("all")
            )
        )
        
        self.scroll_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")

    def init_conn_frame(self):
        tk.Label(self.conn_frame, text="Conexão em rede:").grid(row=0, column=0, padx=5, pady=5)

        self.create_conn_checkbutton.config(text="Criar conexão", variable=self.create_conn_toggle, command=self.check_creating_conn)
        self.create_conn_checkbutton.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(self.conn_frame, text="Host:").grid(row=1, column=0, padx=5, pady=5)
        self.ip_entry.config(textvariable=self.ip)
        self.ip_entry.grid(row=1, column=1, padx=5, pady=5)

        tk.Label(self.conn_frame, text="Porta:").grid(row=2, column=0, padx=5, pady=5)
        self.port_entry.config(textvariable=self.port)
        self.port_entry.grid(row=2, column=1, padx=5, pady=5)

        self.confirm_button.config(text="Confirmar", command=self.connect)
        self.confirm_button.grid(row=3, column=0, columnspan=2, pady=10)

        self.conn_frame.pack(pady=10)

    def check_creating_conn(self):
        if self.create_conn_toggle.get():
            self.ip_entry.config(state=tk.DISABLED)
            self.ip.set(get_ip())
            self.ip_entry.config(textvariable=self.ip)
        else:
            self.ip_entry.config(state=tk.NORMAL)
            self.ip.set('')

    def connect(self):
        print(self.ip.get(), self.port.get())
        try:
            self.host.ip = self.ip.get()
            self.host.port = int(self.port.get())
            if self.create_conn_toggle.get():
                self.host.is_server = True
                self.host.create_connection()
            else:
                self.host.is_server = False
                self.host.connect()
            self.conn_frame.destroy()
            self.init_message_frame()
        except:
            messagebox.showerror("Erro", "Erro ao criar conexão com " + self.ip.get() + ":" + self.port.get() + ".")

    def send_message(self):
        message = self.msg_entry.get()
        print(message)
        if not message:
            messagebox.showerror("Erro", "Digite uma mensagem.")
            return

        encrypted = self.encode_decode.encrypt(message)
        binary = self.encode_decode.ascii_to_binary(self.encode_decode.string_to_ascii(encrypted))
        encoded = self.encode_decode.encode_ami_pseudoternary(binary)
        # encoded = self.encode_decode.encode_ami_pseudoternary("010010")
        print(self.encode_decode.alphabet)

        # Clear previous text and insert new text
        self.msg_encrypted.delete(1.0, tk.END)
        self.msg_encrypted.insert(tk.END, encrypted)

        self.msg_binary.delete(1.0, tk.END)
        self.msg_binary.insert(tk.END, binary)

        self.msg_encoded.delete(1.0, tk.END)
        self.msg_encoded.insert(tk.END, ''.join(encoded))

        print(encoded)
        fig = self.plot_waveform(encoded)

        # Clear the previous canvas if it exists
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        self.canvas = FigureCanvasTkAgg(fig, master=self.waveform_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack()

        self.host.set_message(''.join(encoded))
        self.host.send_message()

    def receive_message(self):
        encoded = self.host.receive_message()

        fig = self.plot_waveform(encoded)

        # Clear the previous canvas if it exists
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        self.canvas = FigureCanvasTkAgg(fig, master=self.waveform_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack()

        binary = self.encode_decode.decode_ami_pseudoternary(encoded)
        encrypted = self.encode_decode.ascii_to_string(self.encode_decode.binary_to_ascii(binary))
        message = self.encode_decode.decrypt(encrypted)

        # Clear previous text and insert new text
        self.msg_encrypted.delete(1.0, tk.END)
        self.msg_encrypted.insert(tk.END, encrypted)

        self.msg_binary.delete(1.0, tk.END)
        self.msg_binary.insert(tk.END, binary)

        self.msg_encoded.delete(1.0, tk.END)
        self.msg_encoded.insert(tk.END, encoded)

        self.msg_entry.delete(0, tk.END)
        self.msg_entry.insert(0, message)

    def init_message_frame(self):
        frame_top = tk.Frame(self.scrollable_frame)
        frame_top.pack(pady=10)

        frame_bottom = tk.Frame(self.scrollable_frame)
        frame_bottom.pack(pady=10)

        tk.Label(frame_top, text="Mensagem:").grid(row=0, column=0, padx=5, pady=5)
        self.msg_entry = tk.Entry(frame_top, width=30)
        self.msg_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Button(frame_top, text="Enviar", command=self.send_message).grid(row=1, column=0, columnspan=2, pady=10)
        tk.Button(frame_top, text="Receber", command=self.receive_message).grid(row=2, column=0, columnspan=2, pady=10)

        tk.Label(frame_bottom, text="Mensagem Criptografada:").grid(row=0, column=0, padx=5, pady=5)
        self.msg_encrypted = scrolledtext.ScrolledText(frame_bottom, width=30, height=5)
        self.msg_encrypted.grid(row=1, column=0, padx=5, pady=5)

        tk.Label(frame_bottom, text="Mensagem em Binário:").grid(row=2, column=0, padx=5, pady=5)
        self.msg_binary = scrolledtext.ScrolledText(frame_bottom, width=30, height=5)
        self.msg_binary.grid(row=3, column=0, padx=5, pady=5)

        tk.Label(frame_bottom, text="Mensagem Codificada:").grid(row=4, column=0, padx=5, pady=5)
        self.msg_encoded = scrolledtext.ScrolledText(frame_bottom, width=30, height=5)
        self.msg_encoded.grid(row=5, column=0, padx=5, pady=5)

        self.waveform_frame = tk.Frame(frame_bottom)
        self.waveform_frame.grid(row=6, column=0, pady=20)

    def plot_waveform(self, encoded_message):
        time = list(range(len(encoded_message)))
        signal = []
        for bit in encoded_message:
            if bit == '0':
                signal.append(0)
            elif bit == '+':
                signal.append(1)
            elif bit == '-':
                signal.append(-1)
        fig, ax = plt.subplots(figsize=(10, 4))
        ax.step(time, signal, where='mid')
        ax.set(title='AMI Pseudoternário', xlabel='Tempo', ylabel='Sinal')
        ax.grid()
        return fig

if __name__ == "__main__":
    root = tk.Tk()
    app = Application(root)
    root.mainloop()
