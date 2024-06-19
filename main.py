word = 'á'
result = []
shift = 14
def criptografar(mensagem):
    print(mensagem)
    list_ascii= []
    for char in mensagem:
        ascii_value = ord(char)
        ascii_value = (ascii_value + shift) % 256
        if ascii_value < 32:
            ascii_value = 32+ascii_value
        list_ascii.append(ascii_value)
    
    string = ''
    for a in list_ascii:
        string=string+chr(a)
    print(list_ascii)
    print(string)
    return string


def descriptografar(mensagem):
    print(mensagem)
    list_ascii= []
    for char in mensagem:
        ascii_value = ord(char)
        ascii_value = (ascii_value - shift) % 256
        if ascii_value > 32:
            ascii_value = ascii_value-32
        list_ascii.append(ascii_value)
    string = ''
    for a in list_ascii:
        string=string+chr(a)
    print(list_ascii)
    print(string)
    return string

teste = 'ù ÿ ñ ò'

print(descriptografar(criptografar(teste)))