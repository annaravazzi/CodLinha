# word = 'á'
# result = []
# shift = 14
# def criptografar(mensagem):
#     print(mensagem)
#     list_ascii= []
#     for char in mensagem:
#         ascii_value = ord(char)
#         ascii_value = (ascii_value + shift) % 256
#         if ascii_value < 32:
#             ascii_value = 32+ascii_value
#         list_ascii.append(ascii_value)
    
#     string = ''
#     for a in list_ascii:
#         string=string+chr(a)
#     print(list_ascii)
#     print(string)
#     return string


# def descriptografar(mensagem):
#     print(mensagem)
#     list_ascii= []
#     for char in mensagem:
#         ascii_value = ord(char)
#         ascii_value = (ascii_value - shift) % 256
#         if ascii_value > 32:
#             ascii_value = ascii_value-32
#         list_ascii.append(ascii_value)
#     string = ''
#     for a in list_ascii:
#         string=string+chr(a)
#     print(list_ascii)
#     print(string)
#     return string

# teste = 'ù ÿ ñ ò'

# print(descriptografar(criptografar(teste)))

# def encrypt(message, alphabet, key):
#     encrypted_message = ""
#     for char in message:
#         i = alphabet.find(char)
#         if i == -1:
#             encrypted_message += char
#         else:
#             encrypted_message += alphabet[(i + key) % len(alphabet)]
#     return encrypted_message

# print(encrypt('a ligeira raposa marrom saltou sobre o cachorro cansado', 'abcdefghijklmnopqrstuvwyzàáãâéêóôõíúçABCDEFGHIJKLMNOPQRSTUVWYZÀÁÃÂÉÊÓÕÍÚÇ', 5))

import encode_decode

encripted = encode_decode.encrypt('a ligeira raposa marrom saltou sobre o cachorro cansado', encode_decode.generate_alphabet(), 5)
binary = encode_decode.ascii_to_binary(encode_decode.string_to_ascii(encripted))
encoded = encode_decode.encode_ami_pseudoternary(binary)

decoded = encode_decode.decode_ami_pseudoternary(encoded)
binary = encode_decode.ascii_to_string(encode_decode.binary_to_ascii(decoded))
decrypted = encode_decode.decrypt(binary, encode_decode.generate_alphabet(), 5)
print(decrypted)