import socket
# Source: https://stackoverflow.com/a/28950776/3057377
def get_ip():
    tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tmp.settimeout(0)
    try:
        tmp.connect(('10.254.254.254', 1))
        ip = tmp.getsockname()[0]
    except:
        ip = '127.0.0.1'
    finally:
        tmp.close()
    return ip

class Host:
    def __init__(self):
        self.conn_socket = socket.socket()
        self.ip = ''
        self.port = 0000
        self.conn = ''
        self.addr = ''

        self.encoded_msg = ''

        self.is_server = False
    
    # Conecta ao outro host
    def connect(self):
        self.conn_socket.connect((self.ip, self.port))
    
    # Inicia a conexão
    def create_connection(self):
        self.conn_socket.bind((self.ip, self.port))
        self.conn_socket.listen(2)
        self.conn, self.addr = self.conn_socket.accept()
    
    def set_message(self, message):
        self.encoded_msg = message

    def send_message(self):
        if self.is_server:
            self.conn.send(self.encoded_msg.encode())
        else:
            self.conn_socket.send(self.encoded_msg.encode())
    
    def receive_message(self):
        if self.is_server:
            return self.conn.recv(1024).decode()
        else:
            return self.conn_socket.recv(1024).decode()