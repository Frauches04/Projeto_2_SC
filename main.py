#!/usr/bin/env python3
# main_simples.py - Versão simplificada para a Parte I do trabalho

import base64
from rsa_oaep import gerar_chaves_rsa, rsa_cifrar_oaep, rsa_decifrar_oaep

def main():
    print("=" * 50)
    print("PARTE I - RSA com OAEP (SHA-3)")
    print("=" * 50)
    
    # 1. Gerar chaves
    print("\n[1] Gerando chaves RSA (p e q com 1024 bits)...")
    chave_publica, chave_privada = gerar_chaves_rsa(bits_pq=1024, e=65537)
    
    # 2. Mensagem a ser cifrada
    mensagem = b"LOVE"
    print(f"\n[2] Mensagem original: {mensagem.decode()}")
    
    # 3. Cifrar com chave pública
    texto_cifrado = rsa_cifrar_oaep(mensagem, chave_publica)
    print(f"\n[3] Texto cifrado (base64): {base64.b64encode(texto_cifrado).decode()}")
    
    # 4. Decifrar com chave privada
    texto_decifrado = rsa_decifrar_oaep(texto_cifrado, chave_privada)
    print(f"\n[4] Texto decifrado: {texto_decifrado.decode()}")
    
    # 5. Verificação
    if mensagem == texto_decifrado:
        print("\n✅ SUCESSO! A mensagem foi cifrada e decifrada corretamente.")
    else:
        print("\n❌ ERRO! A mensagem decifrada não confere com a original.")

if __name__ == "__main__":
    main()