# Gera o alfabeto, composto por todos os caracteres ASCII imprimíveis
def generate_alphabet():
    alphabet = ""
    for i in range(32, 128):
        alphabet += chr(i)
    for i in range(161, 256):
        alphabet += chr(i)
    return alphabet

class EncodeDecode:
    def __init__(self, alphabet, key):
        self.alphabet = alphabet
        self.key = key

    # Criptografa a mensagem com a cifra de César
    def encrypt(self, message):
        encrypted_message = ""
        for char in message:
            i = self.alphabet.find(char)
            if i == -1:
                encrypted_message += char
            else:
                encrypted_message += self.alphabet[(i + self.key) % len(self.alphabet)]
        return encrypted_message

    # Descriptografa a mensagem com a cifra de César
    def decrypt(self, message):
        decrypted_message = ""
        for char in message:
            i = self.alphabet.find(char)
            if i == -1:
                decrypted_message += char
            else:
                decrypted_message += self.alphabet[(i - self.key) % len(self.alphabet)]
        return decrypted_message

    # Converte a mensagem (string) para uma lista de valores ASCII (int)
    def string_to_ascii(self, message):
        list_ascii = []
        for char in message:
            list_ascii.append(ord(char))
        return list_ascii

    # Converte a lista de valores ASCII (int) para uma string
    def ascii_to_string(self, ascii_list):
        string = ""
        for n in ascii_list:
            string += chr(n)
        return string

    # Converte a lista de valores ASCII (int) para bits (string)
    def ascii_to_binary(self, ascii_list):
        binary_list = []
        for n in ascii_list:
            binary_list.append(format(n, '08b'))
        
        return ''.join(binary_list)

    # Converte os bits (string) para a lista de valores ASCII (int)
    def binary_to_ascii(self, binary_message):
        ascii_list = []
        for i in range(0, len(binary_message), 8):
            ascii_list.append(int(binary_message[i:i+8], 2))
        return ascii_list

    # Codificação de linha AMI pseudoternária (bit 0 alternado com + e -, bit 1 = 0)
    # Retorna uma lista de caracteres (+, -, 0)
    def encode_ami_pseudoternary(self, binary_message):
        result = []
        high = True
        for bit in binary_message:
            # bit 1 = tensão zero
            if bit == '1':
                result.append('0')
            # bit 0 = tensão alternada
            else:
                if high:
                    result.append('+')
                else:
                    result.append('-')
                high = not high
        return result

    # Decodificação de linha AMI pseudoternária (bit 0 alternado com + e -, bit 1 = 0)
    # Retorna uma string binária
    def decode_ami_pseudoternary(self, encoded_message):
        binary_message = ""
        for lvl in encoded_message:
            if lvl == '0':
                binary_message += '1'
            elif lvl == '+' or lvl == '-':
                binary_message += '0'
        return binary_message