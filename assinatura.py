#!/usr/bin/env python3
# assinatura.py - Funções para assinatura digital RSA + SHA-3 + Base64

import os
import hashlib
import base64
from typing import Tuple
from rsa_oaep import bytes_para_int, int_para_bytes

# ----------------------------------------------------------------------
# 1. Cálculo de hash SHA3-256 de um arquivo
# ----------------------------------------------------------------------

def hash_arquivo_sha3(caminho: str) -> bytes:
    """
    Lê o arquivo em modo binário e retorna o hash SHA3-256 (32 bytes).
    """
    sha3 = hashlib.sha3_256()
    with open(caminho, 'rb') as f:
        # Lê em blocos para eficiência com arquivos grandes
        for bloco in iter(lambda: f.read(4096), b''):
            sha3.update(bloco)
    return sha3.digest()

# ----------------------------------------------------------------------
# 2. Assinatura RSA (primitiva: (hash)^d mod n)
# ----------------------------------------------------------------------

def assinar_hash(hash_bytes: bytes, chave_privada: Tuple[int, int]) -> bytes:
    """
    Assina o hash usando a chave privada (d, n).
    Retorna a assinatura como bytes (tamanho = bytes de n).
    """
    d, n = chave_privada
    k = (n.bit_length() + 7) // 8          # número de bytes de n
    hash_int = bytes_para_int(hash_bytes)   # converte hash para inteiro
    if hash_int >= n:
        raise ValueError("Hash maior que o módulo RSA (impossível com SHA-256 e n>=2048 bits)")
    sig_int = pow(hash_int, d, n)           # assinatura como inteiro
    return int_para_bytes(sig_int, k)       # converte para bytes

def verificar_assinatura(hash_bytes: bytes, assinatura_bytes: bytes,
                         chave_publica: Tuple[int, int]) -> bool:
    """
    Verifica a assinatura usando a chave pública (e, n).
    Retorna True se a assinatura corresponde ao hash.
    """
    e, n = chave_publica
    sig_int = bytes_para_int(assinatura_bytes)
    hash_recuperado_int = pow(sig_int, e, n)
    hash_original_int = bytes_para_int(hash_bytes)
    return hash_recuperado_int == hash_original_int

# ----------------------------------------------------------------------
# 3. Formatação Base64 com cabeçalho (informações para verificação)
# ----------------------------------------------------------------------

def salvar_assinatura_base64(assinatura_bytes: bytes, caminho_sig: str,
                             nome_arquivo_original: str = "") -> None:
    """
    Salva a assinatura em formato Base64 com cabeçalho contendo metadados.
    Formato:
        -----BEGIN RSA SIGNATURE-----
        Hash: SHA3-256
        File: <nome_arquivo_original>
        
        <assinatura_base64>
        -----END RSA SIGNATURE-----
    """
    assinatura_b64 = base64.b64encode(assinatura_bytes).decode('ascii')
    with open(caminho_sig, 'w') as f:
        f.write("-----BEGIN RSA SIGNATURE-----\n")
        f.write("Hash: SHA3-256\n")
        if nome_arquivo_original:
            f.write(f"File: {nome_arquivo_original}\n")
        f.write("\n")  # linha em branco separadora
        # Quebra a linha Base64 a cada 64 caracteres (opcional, fica mais legível)
        for i in range(0, len(assinatura_b64), 64):
            f.write(assinatura_b64[i:i+64] + "\n")
        f.write("-----END RSA SIGNATURE-----\n")

def carregar_assinatura_base64(caminho_sig: str) -> bytes:
    """
    Lê um arquivo de assinatura formatado e retorna os bytes da assinatura.
    Ignora linhas de cabeçalho (que começam com '-' ou contêm ':').
    """
    linhas = []
    with open(caminho_sig, 'r') as f:
        for linha in f:
            linha = linha.strip()
            if not linha:
                continue
            if linha.startswith('-') or ':' in linha:
                continue
            linhas.append(linha)
    # Junta todas as linhas restantes (que devem ser a Base64)
    b64_str = ''.join(linhas)
    return base64.b64decode(b64_str)

# ----------------------------------------------------------------------
# 4. Funções de alto nível (assinar arquivo, verificar arquivo)
# ----------------------------------------------------------------------

def assinar_arquivo(caminho_arquivo: str, caminho_chave_privada: str,
                    caminho_saida_sig: str) -> None:
    """
    Assina um arquivo usando a chave privada fornecida.
    """
    # Carrega chave privada (formato: duas linhas: d e n)
    with open(caminho_chave_privada, 'r') as f:
        d = int(f.readline().strip())
        n = int(f.readline().strip())
    chave_priv = (d, n)

    # Calcula hash do arquivo
    hash_bytes = hash_arquivo_sha3(caminho_arquivo)

    # Gera assinatura
    assinatura_bytes = assinar_hash(hash_bytes, chave_priv)

    # Salva em Base64 com cabeçalho
    nome_base = os.path.basename(caminho_arquivo)
    salvar_assinatura_base64(assinatura_bytes, caminho_saida_sig, nome_base)
    print(f"Assinatura gerada e salva em: {caminho_saida_sig}")

def verificar_arquivo(caminho_arquivo: str, caminho_chave_publica: str,
                      caminho_sig: str) -> bool:
    """
    Verifica a assinatura de um arquivo.
    Retorna True se válida, False caso contrário.
    """
    # Carrega chave pública (formato: duas linhas: e e n)
    with open(caminho_chave_publica, 'r') as f:
        e = int(f.readline().strip())
        n = int(f.readline().strip())
    chave_pub = (e, n)

    # Calcula hash do arquivo
    hash_bytes = hash_arquivo_sha3(caminho_arquivo)

    # Carrega assinatura
    assinatura_bytes = carregar_assinatura_base64(caminho_sig)

    # Verifica
    return verificar_assinatura(hash_bytes, assinatura_bytes, chave_pub)