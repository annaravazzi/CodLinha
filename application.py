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

        # Cria um objeto da classe Host
        self.host = Host()

        # Cria um objeto da classe EncodeDecode
        self.encode_decode = EncodeDecode(generate_alphabet(), KEY)

        self.root = root
        self.root.title("Codificação AMI Pseudoternário")

        self.receive_toggle = tk.BooleanVar()
        self.receive_toggle.set(False)

        # Frame de conexão
        self.conn_frame = tk.Frame(root)
        self.create_conn_toggle = tk.BooleanVar()
        # self.connect_toggle = tk.BooleanVar()
        self.create_conn_checkbutton = tk.Checkbutton(self.conn_frame)
        # self.connect_checkbutton = tk.Checkbutton(self.conn_frame)
        self.confirm_button = tk.Button(self.conn_frame)
        self.ip = tk.StringVar()
        self.port = tk.StringVar()
        self.ip_entry = tk.Entry(self.conn_frame)
        self.port_entry = tk.Entry(self.conn_frame)

        self.init_conn_frame()

    def init_conn_frame(self):
        tk.Label(self.conn_frame, text="Conexão em rede:").grid(row=0, column=0, padx=5, pady=5)

        self.create_conn_checkbutton.config(text="Criar conexão", variable=self.create_conn_toggle, command=self.check_creating_conn)
        self.create_conn_checkbutton.grid(row=0, column=1, padx=5, pady=5)
        # self.connect_checkbutton.config(text="Conectar", variable=self.connect_toggle, command=self.check_connecting)
        # self.connect_checkbutton.grid(row=0, column=2, padx=5, pady=5)

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
            # self.connect_checkbutton.config(state=tk.DISABLED)
            self.ip_entry.config(state=tk.DISABLED)
            # self.confirm_button.config(state=tk.NORMAL)
            self.ip.set(get_ip())
            self.ip_entry.config(textvariable=self.ip)
        else:
            # self.connect_checkbutton.config(state=tk.NORMAL)
            self.ip_entry.config(state=tk.NORMAL)
            # self.confirm_button.config(state=tk.DISABLED)
            self.ip.set('')

    # def check_connecting(self):
    #     if self.connect_toggle.get():
    #         self.create_conn_checkbutton.config(state=tk.DISABLED)
    #         self.host_entry.config(state=tk.DISABLED)
    #         self.confirm_button.config(state=tk.NORMAL)
    #         self.host.set(get_ip())
    #     else:
    #         self.create_conn_checkbutton.config(state=tk.NORMAL)
    #         self.host_entry.config(state=tk.NORMAL)
    #         self.confirm_button.config(state=tk.DISABLED)
    #         self.host.set('')

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
        if not message:
            messagebox.showerror("Erro", "Digite uma mensagem.")
            return

        # Criptografia e codificação da mensagem
        encrypted = EncodeDecode.encrypt(message)
        binary = EncodeDecode.ascii_to_binary(EncodeDecode.string_to_ascii(encrypted))
        encoded = EncodeDecode.encode_ami_pseudoternary(binary)
        # encoded = encode_decode.encode_ami_pseudoternary("010010")
        print(EncodeDecode.alphabet)

        # Atualiza os campos de texto
        self.msg_encrypted.insert(tk.END, encrypted + "\n")
        self.msg_binary.insert(tk.END, binary + "\n")
        self.msg_encoded.insert(tk.END, ''.join(encoded) + "\n")

        # Plota a forma de onda
        fig = self.plot_waveform(encoded)
        canvas = FigureCanvasTkAgg(fig, master=self.waveform_frame)
        canvas.draw()
        canvas.get_tk_widget().pack()

        # Envia a mensagem
        self.host.set_message(''.join(encoded))
        self.host.send_message()

    def receive_message(self):
        encoded = self.host.receive_message()
        binary = EncodeDecode.decode_ami_pseudoternary(encoded)
        encrypted = EncodeDecode.ascii_to_string(EncodeDecode.binary_to_ascii(binary))
        message = EncodeDecode.decrypt(encrypted)

        # Atualiza os campos de texto
        self.msg_encrypted.insert(tk.END, encrypted + "\n")
        self.msg_binary.insert(tk.END, binary + "\n")
        self.msg_encoded.insert(tk.END, encoded + "\n")
        self.msg_entry.insert(tk.END, message + "\n")

        # Plota a forma de onda
        fig = self.plot_waveform(encoded)
        canvas = FigureCanvasTkAgg(fig, master=self.waveform_frame)
        canvas.draw()
        canvas.get_tk_widget().pack()

    def init_message_frame(self):
        frame_top = tk.Frame(root)
        frame_top.pack(pady=10)

        frame_bottom = tk.Frame(root)
        frame_bottom.pack(pady=10)

        tk.Label(frame_top, text="Mensagem:").grid(row=0, column=0, padx=5, pady=5)
        self.msg_entry = tk.Entry(frame_top, width=50)
        self.msg_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Button(frame_top, text="Enviar", command=self.send_message).grid(row=1, column=0, columnspan=2, pady=10)
        tk.Button(frame_top, text="Receber", command=self.receive_message).grid(row=1, column=0, columnspan=2, pady=10)

        tk.Label(frame_bottom, text="Mensagem Criptografada:").grid(row=0, column=0, padx=5, pady=5)
        self.msg_encrypted = scrolledtext.ScrolledText(frame_bottom, width=60, height=5)
        self.msg_encrypted.grid(row=1, column=0, padx=5, pady=5)

        tk.Label(frame_bottom, text="Mensagem em Binário:").grid(row=2, column=0, padx=5, pady=5)
        self.msg_binary = scrolledtext.ScrolledText(frame_bottom, width=60, height=5)
        self.msg_binary.grid(row=3, column=0, padx=5, pady=5)

        tk.Label(frame_bottom, text="Mensagem Codificada:").grid(row=4, column=0, padx=5, pady=5)
        self.msg_encoded = scrolledtext.ScrolledText(frame_bottom, width=60, height=5)
        self.msg_encoded.grid(row=5, column=0, padx=5, pady=5)

        self.waveform_frame = tk.Frame(frame_bottom)
        self.waveform_frame.grid(row=6, column=0, pady=20)

    # Plota a forma de onda da mensagem codificada
    def plot_waveform(encoded_message):
        time = list(range(len(encoded_message)))
        signal = []
        for bit in encoded_message:
            if bit == '0':
                signal.append(0)
            elif bit == '+':
                signal.append(1)
            elif bit == '-':
                signal.append(-1)
        fig, ax = plt.subplots()
        ax.step(time, signal, where='mid')
        ax.set(title='AMI Pseudoternário', xlabel='Tempo', ylabel='Sinal')
        ax.grid()
        return fig


    # # Example communication function (replace with actual network communication)
    # def communicate(self, message):
    #     host = '127.0.0.1'  # IP do servidor
    #     port = 65432        # Porta do servidor
    #     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    #         s.connect((host, port))
    #         s.sendall(message.encode('utf-8'))

if __name__ == "__main__":
    root = tk.Tk()
    app = Application(root)
    root.mainloop()