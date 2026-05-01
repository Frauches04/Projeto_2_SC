#!/usr/bin/env python3
# app_assinatura.py - CLI para assinatura digital (Parte II)

import sys
import argparse
from rsa_oaep import gerar_chaves_rsa
from assinatura import assinar_arquivo, verificar_arquivo

def main():
    parser = argparse.ArgumentParser(
        description="Ferramenta de assinatura digital RSA + SHA3-256 (Parte II do trabalho)"
    )
    subparsers = parser.add_subparsers(dest='comando', required=True)

    # Comando: gerar chaves
    parser_gen = subparsers.add_parser('gen', help='Gerar par de chaves RSA')
    parser_gen.add_argument('--bits', type=int, default=1024,
                            help='Tamanho de p e q em bits (padrão 1024)')
    parser_gen.add_argument('--pub', default='chave_publica.key',
                            help='Arquivo para salvar a chave pública')
    parser_gen.add_argument('--priv', default='chave_privada.key',
                            help='Arquivo para salvar a chave privada')

    # Comando: assinar
    parser_sign = subparsers.add_parser('sign', help='Assinar um arquivo')
    parser_sign.add_argument('arquivo', help='Arquivo a ser assinado')
    parser_sign.add_argument('--priv', required=True,
                             help='Arquivo da chave privada')
    parser_sign.add_argument('--sig', default='',
                             help='Arquivo de saída da assinatura (padrão: arquivo.sig)')

    # Comando: verificar
    parser_verify = subparsers.add_parser('verify', help='Verificar assinatura')
    parser_verify.add_argument('arquivo', help='Arquivo original')
    parser_verify.add_argument('--pub', required=True,
                               help='Arquivo da chave pública')
    parser_verify.add_argument('--sig', required=True,
                               help='Arquivo da assinatura (.sig)')

    args = parser.parse_args()

    if args.comando == 'gen':
        print(f"Gerando chaves RSA com {args.bits} bits em p e q...")
        pub, priv = gerar_chaves_rsa(bits_pq=args.bits, e=65537)
        with open(args.pub, 'w') as f:
            f.write(f"{pub[0]}\n{pub[1]}")
        with open(args.priv, 'w') as f:
            f.write(f"{priv[0]}\n{priv[1]}")
        print(f"Chave pública salva em: {args.pub}")
        print(f"Chave privada salva em: {args.priv}")

    elif args.comando == 'sign':
        sig_file = args.sig if args.sig else args.arquivo + ".sig"
        assinar_arquivo(args.arquivo, args.priv, sig_file)

    elif args.comando == 'verify':
        valido = verificar_arquivo(args.arquivo, args.pub, args.sig)
        if valido:
            print("✅ Assinatura VÁLIDA. O arquivo é autêntico e não foi alterado.")
        else:
            print("❌ Assinatura INVÁLIDA. O arquivo pode ter sido modificado ou a chave não corresponde.")
            sys.exit(1)

if __name__ == '__main__':
    main()