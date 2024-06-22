import tkinter as tk
from tkinter import messagebox, scrolledtext
import socket
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import encode_decode

KEY = 14

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

# Interface gráfica
class Application:
    def __init__(self, root):

        # Disposição da janela
        self.root = root
        self.root.title("Codificação AMI Pseudoternário")

        frame_top = tk.Frame(root)
        frame_top.pack(pady=10)

        frame_bottom = tk.Frame(root)
        frame_bottom.pack(pady=10)

        tk.Label(frame_top, text="Mensagem:").grid(row=0, column=0, padx=5, pady=5)
        self.msg_entry = tk.Entry(frame_top, width=50)
        self.msg_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Button(frame_top, text="Enviar", command=self.send_message).grid(row=1, column=0, columnspan=2, pady=10)

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

    def send_message(self):
        message = self.msg_entry.get()
        if not message:
            messagebox.showerror("Erro", "Digite uma mensagem.")
            return

        # Criptografia e codificação da mensagem
        alphabet = encode_decode.generate_alphabet()
        encrypted = encode_decode.encrypt(message, alphabet, KEY)
        binary = encode_decode.ascii_to_binary(encode_decode.string_to_ascii(encrypted))
        encoded = encode_decode.encode_ami_pseudoternary(binary)
        # encoded = encode_decode.encode_ami_pseudoternary("010010")
        print(alphabet)

        # Atualiza os campos de texto
        self.msg_encrypted.insert(tk.END, encrypted + "\n")
        self.msg_binary.insert(tk.END, binary + "\n")
        self.msg_encoded.insert(tk.END, ''.join(encoded) + "\n")

        # Plota a forma de onda
        fig = plot_waveform(encoded)
        canvas = FigureCanvasTkAgg(fig, master=self.waveform_frame)
        canvas.draw()
        canvas.get_tk_widget().pack()

        # Communication (example code, replace with actual network code)
        # self.communicate(''.join(codificada))

    def receive_message(self):
        encoded = ""
        binary = encode_decode.decode_ami_pseudoternary(encoded)
        decrypted = encode_decode.ascii_to_string(encode_decode.binary_to_ascii(binary))


    # Example communication function (replace with actual network communication)
    def communicate(self, message):
        host = '127.0.0.1'  # IP do servidor
        port = 65432        # Porta do servidor
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.sendall(message.encode('utf-8'))

if __name__ == "__main__":
    root = tk.Tk()
    app = Application(root)
    root.mainloop()