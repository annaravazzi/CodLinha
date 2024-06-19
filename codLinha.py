import tkinter as tk
from tkinter import messagebox, scrolledtext
import socket
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


def criptografar(mensagem):
    return ''.join(chr(ord(char) + 1) for char in mensagem)

def descriptografar(mensagem):
    return ''.join(chr(ord(char) - 1) for char in mensagem)

def to_binary(mensagem):
    return ''.join(format(ord(char), '08b') for char in mensagem)

#ami  pseudoternario ou bipolar(0 é codificado sem pulso e 1 é alternado entre positivo e negativo)
def ami_pseudoternary(binary_message):
    result = []
    positive = True
    for bit in binary_message:
        if bit == '0':
            result.append('0')
        else:

            if positive:
                result.append('+')
            else:
                result.append('-')
            positive = not positive
    return result

def plot_waveform(encoded_message):
    time = list(range(len(encoded_message)))
    signal = []
    level = 0
    for bit in encoded_message:
        if bit == '0':
            signal.append(level)
        elif bit == '+':
            level = 1
            signal.append(level)
        elif bit == '-':
            level = -1
            signal.append(level)
    fig, ax = plt.subplots()
    ax.step(time, signal, where='mid')
    ax.set(title='Ami Pseudoternary Waveform', xlabel='Time', ylabel='Signal Level')
    ax.grid()
    return fig

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Codificação Ami Pseudoternário")

        # Frames
        frame_top = tk.Frame(root)
        frame_top.pack(pady=10)

        frame_bottom = tk.Frame(root)
        frame_bottom.pack(pady=10)

        # Labels and Text Inputs
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

        # Placeholder for waveform plot
        self.waveform_frame = tk.Frame(frame_bottom)
        self.waveform_frame.grid(row=6, column=0, pady=20)

    def send_message(self):
        mensagem = self.msg_entry.get()
        if not mensagem:
            messagebox.showerror("Erro", "Digite uma mensagem.")
            return

        criptografada = criptografar(mensagem)
        binaria = to_binary(criptografada)
        codificada = ami_pseudoternary(binaria)

        # Display results
        self.msg_encrypted.insert(tk.END, criptografada + "\n")
        self.msg_binary.insert(tk.END, binaria + "\n")
        self.msg_encoded.insert(tk.END, ''.join(codificada) + "\n")

        # Plot waveform
        fig = plot_waveform(codificada)
        canvas = FigureCanvasTkAgg(fig, master=self.waveform_frame)
        canvas.draw()
        canvas.get_tk_widget().pack()

        # Communication (example code, replace with actual network code)
        # self.communicate(''.join(codificada))

    # Example communication function (replace with actual network communication)
    def communicate(self, message):
        host = '127.0.0.1'  # IP do servidor
        port = 65432        # Porta do servidor
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.sendall(message.encode('utf-8'))

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
