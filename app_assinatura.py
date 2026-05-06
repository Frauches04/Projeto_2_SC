import sys
import argparse
from rsa_oaep import gerar_chaves_rsa, rsa_cifrar_oaep, rsa_decifrar_oaep
from assinatura import assinar_arquivo, verificar_arquivo

def main():
    parser = argparse.ArgumentParser(
        description="Ferramenta RSA-OAEP: geração de chaves, cifração/decifração, assinatura/verificação"
    )
    subparsers = parser.add_subparsers(dest='comando', required=True)

    # ------------------------------------------------------------------
    # Comando: gerar chaves RSA 
    # ------------------------------------------------------------------
    parser_gen = subparsers.add_parser('gen', help='Gerar par de chaves RSA')
    parser_gen.add_argument('--bits', type=int, default=1024,
                            help='Tamanho de p e q em bits (mínimo 1024, padrão 1024)')
    parser_gen.add_argument('--pub', default='chave_publica.key',
                            help='Arquivo para salvar a chave pública')
    parser_gen.add_argument('--priv', default='chave_privada.key',
                            help='Arquivo para salvar a chave privada')

    # ------------------------------------------------------------------
    # cifrar mensagem/arquivo com RSA-OAEP
    # ------------------------------------------------------------------
    parser_enc = subparsers.add_parser('encrypt', help='Cifrar um arquivo/mensagem com RSA-OAEP')
    parser_enc.add_argument('--pub', required=True,
                            help='Arquivo da chave pública (formato: duas linhas com e e n)')
    parser_enc.add_argument('--input', required=True,
                            help='Arquivo de entrada (dados em binário)')
    parser_enc.add_argument('--output', required=True,
                            help='Arquivo de saída cifrado')

    # ------------------------------------------------------------------
    # decifrar mensagem/arquivo com RSA-OAEP 
    # ------------------------------------------------------------------
    parser_dec = subparsers.add_parser('decrypt', help='Decifrar um arquivo cifrado com RSA-OAEP')
    parser_dec.add_argument('--priv', required=True,
                            help='Arquivo da chave privada (formato: duas linhas com d e n)')
    parser_dec.add_argument('--input', required=True,
                            help='Arquivo cifrado de entrada')
    parser_dec.add_argument('--output', required=True,
                            help='Arquivo de saída decifrado')

    # ------------------------------------------------------------------
    # assinar arquivo 
    # ------------------------------------------------------------------
    parser_sign = subparsers.add_parser('sign', help='Assinar um arquivo (RSA + SHA3-256)')
    parser_sign.add_argument('arquivo', help='Arquivo a ser assinado')
    parser_sign.add_argument('--priv', required=True,
                             help='Arquivo da chave privada')
    parser_sign.add_argument('--sig', default='',
                             help='Arquivo de saída da assinatura (padrão: arquivo.sig)')

    # ------------------------------------------------------------------
    # verificar assinatura 
    # ------------------------------------------------------------------
    parser_verify = subparsers.add_parser('verify', help='Verificar assinatura de um arquivo')
    parser_verify.add_argument('arquivo', help='Arquivo original')
    parser_verify.add_argument('--pub', required=True,
                               help='Arquivo da chave pública')
    parser_verify.add_argument('--sig', required=True,
                               help='Arquivo da assinatura (.sig)')

    args = parser.parse_args()

    # ------------------------------------------------------------------
    # geração de chaves 
    # ------------------------------------------------------------------
    if args.comando == 'gen':
        if args.bits < 1024:
            print(f"❌ Erro: p e q devem ter no mínimo 1024 bits (solicitado: {args.bits}).", file=sys.stderr)
            sys.exit(1)
        print(f"Gerando chaves RSA com {args.bits} bits em p e q...")
        pub, priv = gerar_chaves_rsa(bits_pq=args.bits, e=65537)
        with open(args.pub, 'w') as f:
            f.write(f"{pub[0]}\n{pub[1]}")
        with open(args.priv, 'w') as f:
            f.write(f"{priv[0]}\n{priv[1]}")
        print(f"Chave pública salva em: {args.pub}")
        print(f"Chave privada salva em: {args.priv}")

    # ------------------------------------------------------------------
    # cifração RSA-OAEP
    # ------------------------------------------------------------------
    elif args.comando == 'encrypt':
        # Carregar chave pública
        with open(args.pub, 'r') as f:
            e = int(f.readline().strip())
            n = int(f.readline().strip())
        chave_pub = (e, n)

        # Ler arquivo de entrada (binário)
        with open(args.input, 'rb') as f:
            dados = f.read()

        # Cifrar
        try:
            cifrado = rsa_cifrar_oaep(dados, chave_pub)
        except ValueError as e:
            print(f"❌ Erro durante a cifração: {e}", file=sys.stderr)
            print("   (Mensagem muito longa para o tamanho da chave?)", file=sys.stderr)
            sys.exit(1)

        # Salvar cifrado
        with open(args.output, 'wb') as f:
            f.write(cifrado)
        print(f"✅ Arquivo cifrado salvo em: {args.output}")

    # ------------------------------------------------------------------
    # decifração RSA-OAEP
    # ------------------------------------------------------------------
    elif args.comando == 'decrypt':
        # Carregar chave privada
        with open(args.priv, 'r') as f:
            d = int(f.readline().strip())
            n = int(f.readline().strip())
        chave_priv = (d, n)

        # Ler arquivo cifrado
        with open(args.input, 'rb') as f:
            cifrado = f.read()

        # Decifrar
        try:
            decifrado = rsa_decifrar_oaep(cifrado, chave_priv)
        except ValueError as e:
            print(f"❌ Erro durante a decifração: {e}", file=sys.stderr)
            sys.exit(1)

        # Salvar decifrado
        with open(args.output, 'wb') as f:
            f.write(decifrado)
        print(f"✅ Arquivo decifrado salvo em: {args.output}")

    # ------------------------------------------------------------------
    # assinatura digital 
    # ------------------------------------------------------------------
    elif args.comando == 'sign':
        sig_file = args.sig if args.sig else args.arquivo + ".sig"
        assinar_arquivo(args.arquivo, args.priv, sig_file)

    # ------------------------------------------------------------------
    # verificação de assinatura 
    # ------------------------------------------------------------------
    elif args.comando == 'verify':
        valido = verificar_arquivo(args.arquivo, args.pub, args.sig)
        if valido:
            print("✅ Assinatura VÁLIDA. O arquivo é autêntico e não foi alterado.")
        else:
            print("❌ Assinatura INVÁLIDA. O arquivo pode ter sido modificado ou a chave não corresponde.")
            sys.exit(1)

if __name__ == '__main__':
    main()