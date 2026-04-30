import os
import random
import math
import hashlib
from typing import Tuple, Callable

# ----------------------------------------------------------------------
# 1. Funções auxiliares aritméticas e de conversão
# ----------------------------------------------------------------------

def euclides_estendido(a: int, b: int) -> Tuple[int, int, int]:
    """
    Algoritmo de Euclides estendido.
    Retorna (x, y, mdc) tal que a*x + b*y = mdc(a,b)
    """
    if b == 0:
        return 1, 0, a
    x1, y1, mdc = euclides_estendido(b, a % b)
    return y1, x1 - (a // b) * y1, mdc

def inverso_modular(a: int, m: int) -> int:
    """
    Calcula o inverso modular de a módulo m.
    Retorna x tal que (a * x) % m == 1
    """
    x, y, g = euclides_estendido(a, m)
    if g != 1:
        raise ValueError("Inverso modular não existe")
    return x % m

def int_para_bytes(x: int, tamanho: int) -> bytes:
    """Converte inteiro para bytes (big-endian) com tamanho fixo."""
    return x.to_bytes(tamanho, byteorder='big')

def bytes_para_int(b: bytes) -> int:
    """Converte bytes para inteiro (big-endian)."""
    return int.from_bytes(b, byteorder='big')

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """Operação XOR byte a byte. Se tamanhos diferentes, trunca no menor."""
    return bytes(x ^ y for x, y in zip(a, b))

# ----------------------------------------------------------------------
# 2. Teste de primalidade Miller–Rabin
# ----------------------------------------------------------------------

# SIGNIFICADO DAS SIGLAS:
# Miller-Rabin = algoritmo probabilístico para testar primalidade
# n = número a ser testado
# k = número de rodadas do teste (precisão)
# d = parte ímpar de n-1 (n-1 = d * 2^s)
# s = expoente de 2 em n-1 (quantidade de divisões por 2)

def eh_primo_miller_rabin(n: int, rodadas: int = 40) -> bool:
    """
    Teste de primalidade probabilístico Miller–Rabin.
    n: número a testar (ímpar > 2)
    rodadas: número de rodadas (precisão)
    Retorna True se n é provavelmente primo.
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Escreve n-1 como d * 2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    def testa_composto(a: int) -> bool:
        """Testa se a base 'a' revela que n é composto."""
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return False
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                return False
        return True  # composto

    for _ in range(rodadas):
        a = random.randrange(2, n - 1)
        if testa_composto(a):
            return False
    return True

def gerar_primo(bits: int) -> int:
    """Gera um número primo ímpar com exatamente 'bits' bits."""
    while True:
        # Gera número ímpar com o bit mais significativo = 1
        num = random.getrandbits(bits)
        num |= (1 << (bits - 1)) | 1   # garante tamanho e ímpar
        if eh_primo_miller_rabin(num):
            return num

# ----------------------------------------------------------------------
# 3. Geração de chaves RSA
# ----------------------------------------------------------------------

# SIGNIFICADO DAS SIGLAS NA CRIPTOGRAFIA RSA:
# RSA = Rivest-Shamir-Adleman (algoritmo de criptografia assimétrica)
# p, q = números primos grandes usados para gerar as chaves
# n = módulo (produto p * q) - usado em ambas as chaves
# φ(n) ou phi = (p-1)*(q-1) - função totiente de Euler
# e = expoente público (padrão 65537) - parte da chave pública
# d = expoente privado (inverso de e módulo φ(n)) - parte da chave privada

def gerar_chaves_rsa(bits_pq: int = 1024, e: int = 65537) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """
    Gera um par de chaves RSA.
    bits_pq: tamanho em bits de p e q (mínimo 1024)
    e: expoente público (padrão 65537)
    Retorna: (chave_publica, chave_privada) onde cada chave é (expoente, modulo)
    """
    print(f"Gerando primo p com {bits_pq} bits...")
    p = gerar_primo(bits_pq)
    print("Gerando primo q ...")
    q = gerar_primo(bits_pq)
    while q == p:
        q = gerar_primo(bits_pq)
    
    n = p * q              # módulo RSA
    phi = (p - 1) * (q - 1)  # função totiente de Euler

    # Garantir que e e phi sejam coprimos (muito raro com e=65537)
    if math.gcd(e, phi) != 1:
        raise ValueError("e não é coprimo com phi. Tente outro expoente.")
    
    d = inverso_modular(e, phi)  # expoente privado
    print("Chaves geradas com sucesso.")
    return (e, n), (d, n)

# ----------------------------------------------------------------------
# 4. MGF1 (Mask Generation Function) baseada em SHA-3
# ----------------------------------------------------------------------

# SIGNIFICADO:
# MGF1 = Mask Generation Function 1 (Função Geradora de Máscara versão 1)
# seed = semente (valor aleatório inicial que será expandido)
# length = comprimento desejado da saída em bytes
# hash_func = função hash utilizada (SHA-3 no nosso caso)
# counter = contador para gerar blocos sequenciais
# hlen = comprimento do hash em bytes (hash length)

def mgf1(semente: bytes, comprimento: int, funcao_hash: Callable = hashlib.sha3_256) -> bytes:
    """
    MGF1 conforme RFC 8017.
    funcao_hash: função hash que retorna um objeto hash (ex: hashlib.sha3_256)
    """
    tamanho_hash = funcao_hash().digest_size
    contador = 0
    saida = b''
    while len(saida) < comprimento:
        c = contador.to_bytes(4, byteorder='big')
        saida += funcao_hash(semente + c).digest()
        contador += 1
    return saida[:comprimento]

# ----------------------------------------------------------------------
# 5. OAEP (Encoding e Decoding)
# ----------------------------------------------------------------------

# SIGNIFICADO DAS SIGLAS NO OAEP:
# OAEP = Optimal Asymmetric Encryption Padding (Preenchimento Ótimo para Criptografia Assimétrica)
# 
# lHash = hash do label (hash do rótulo opcional L)
# PS = Padding String (sequência de zeros para preenchimento)
# DB = Data Block (bloco de dados) = lHash || PS || 0x01 || M
# seed = semente aleatória (gerada a cada cifração)
# MGF = Mask Generation Function (função geradora de máscara)
# maskedDB = DB mascarado (DB XOR MGF(seed))
# maskedSeed = seed mascarado (seed XOR MGF(maskedDB))
# EM = Encoded Message (mensagem codificada) = 0x00 || maskedSeed || maskedDB
# k = comprimento do módulo RSA em bytes

def oaep_codificar(mensagem: bytes, k: int, rotulo: bytes = b'',
                   funcao_hash: Callable = hashlib.sha3_256) -> bytes:
    """
    Empacota a mensagem com OAEP (EME-OAEP encoding).
    k: número de bytes do módulo RSA (tamanho do bloco EM)
    rotulo: rótulo opcional (normalmente vazio)
    Retorna EM (mensagem codificada) de comprimento k bytes.
    """
    tamanho_hash = funcao_hash().digest_size
    tamanho_msg = len(mensagem)
    max_tamanho_msg = k - 2 * tamanho_hash - 2
    if tamanho_msg > max_tamanho_msg:
        raise ValueError(f"Mensagem muito longa (máx {max_tamanho_msg} bytes)")

    hash_rotulo = funcao_hash(rotulo).digest()  # lHash

    # PS = sequência de zeros
    tamanho_ps = k - tamanho_msg - 2 * tamanho_hash - 2
    ps = b'\x00' * tamanho_ps

    # DB = lHash || PS || 0x01 || M
    bloco_dados = hash_rotulo + ps + b'\x01' + mensagem

    # Semente aleatória
    semente = os.urandom(tamanho_hash)  # seed

    # maskedDB = DB xor MGF(semente, k - tamanho_hash - 1)
    mascara_db = mgf1(semente, k - tamanho_hash - 1, funcao_hash)
    db_mascarado = xor_bytes(bloco_dados, mascara_db[:len(bloco_dados)])

    # maskedSeed = semente xor MGF(maskedDB, tamanho_hash)
    mascara_semente = mgf1(db_mascarado, tamanho_hash, funcao_hash)
    semente_mascarada = xor_bytes(semente, mascara_semente[:tamanho_hash])

    # EM = 0x00 || maskedSeed || maskedDB
    msg_codificada = b'\x00' + semente_mascarada + db_mascarado
    if len(msg_codificada) != k:
        raise RuntimeError("Erro interno: EM com tamanho incorreto")
    return msg_codificada

def oaep_decodificar(msg_codificada: bytes, k: int, rotulo: bytes = b'',
                     funcao_hash: Callable = hashlib.sha3_256) -> bytes:
    """
    Desempacota uma mensagem OAEP (EME-OAEP decoding).
    Retorna a mensagem original ou levanta exceção 'erro de decifração'.
    """
    tamanho_hash = funcao_hash().digest_size
    if len(msg_codificada) != k or k < 2 * tamanho_hash + 2:
        raise ValueError("erro de decifração")
    if msg_codificada[0] != 0:
        raise ValueError("erro de decifração")

    semente_mascarada = msg_codificada[1:1 + tamanho_hash]
    db_mascarado = msg_codificada[1 + tamanho_hash:]

    # Recuperar semente
    mascara_semente = mgf1(db_mascarado, tamanho_hash, funcao_hash)
    semente = xor_bytes(semente_mascarada, mascara_semente[:tamanho_hash])

    # Recuperar DB
    mascara_db = mgf1(semente, k - tamanho_hash - 1, funcao_hash)
    bloco_dados = xor_bytes(db_mascarado, mascara_db[:len(db_mascarado)])

    # Separar lHash, PS e mensagem
    hash_rotulo = funcao_hash(rotulo).digest()
    hash_rotulo_db = bloco_dados[:tamanho_hash]
    if hash_rotulo_db != hash_rotulo:
        raise ValueError("erro de decifração")

    resto = bloco_dados[tamanho_hash:]
    try:
        separador = resto.index(b'\x01')
    except ValueError:
        raise ValueError("erro de decifração")

    # Verificar se todos os bytes antes do separador são zero
    ps = resto[:separador]
    if any(b != 0 for b in ps):
        raise ValueError("erro de decifração")

    mensagem = resto[separador + 1:]
    return mensagem

# ----------------------------------------------------------------------
# 6. Cifração e Decifração RSA com OAEP
# ----------------------------------------------------------------------

def rsa_cifrar_oaep(mensagem: bytes, chave_publica: Tuple[int, int], rotulo: bytes = b'') -> bytes:
    """
    Cifra uma mensagem usando RSA-OAEP com chave pública.
    chave_publica = (e, n)
    Retorna texto cifrado (bytes de tamanho k = comprimento de n em bytes).
    """
    e, n = chave_publica
    k = (n.bit_length() + 7) // 8   # bytes do módulo
    msg_codificada = oaep_codificar(mensagem, k, rotulo, hashlib.sha3_256)
    inteiro_msg = bytes_para_int(msg_codificada)
    inteiro_cifrado = pow(inteiro_msg, e, n)
    return int_para_bytes(inteiro_cifrado, k)

def rsa_decifrar_oaep(texto_cifrado: bytes, chave_privada: Tuple[int, int], rotulo: bytes = b'') -> bytes:
    """
    Decifra um texto cifrado RSA-OAEP com chave privada.
    chave_privada = (d, n)
    Retorna a mensagem original.
    """
    d, n = chave_privada
    k = (n.bit_length() + 7) // 8
    if len(texto_cifrado) != k:
        raise ValueError("erro de decifração: tamanho do texto cifrado inválido")
    inteiro_cifrado = bytes_para_int(texto_cifrado)
    inteiro_msg = pow(inteiro_cifrado, d, n)
    msg_codificada = int_para_bytes(inteiro_msg, k)
    return oaep_decodificar(msg_codificada, k, rotulo, hashlib.sha3_256)
