# RSA Signature & Encryption Tool – Trabalho 2 (CIC0201)

**Autores:** Gustavo Henrique Andrade Cavalcanti (Matr. 222034109),
             Heitor Fernandes Estevam (Matr. 231011453),
             Arthur Arruda Frauches (Matr. 241017728),
             Vitor Guedes (Matr. 221017130).
  
**Data de entrega:** 07/05/2026  

---

## 1. Descrição geral

Implementação em Python 3 de um sistema de **assinatura digital RSA** e **cifração assimétrica com OAEP**, atendendo aos requisitos do Trabalho de Implementação 2.

**Arquivos fornecidos:**
- `app_assinatura.py` – interface de linha de comando (CLI)
- `assinatura.py` – hash SHA3‑256, assinatura/verificação, Base64
- `rsa_oaep.py` – Miller‑Rabin, RSA, OAEP, MGF1

---

## 2. Requisitos de ambiente

- Python 3.6 ou superior (recomendado 3.8+)
- Nenhuma biblioteca externa – apenas módulos padrão (`hashlib`, `argparse`, `os`, `random`, `math`, `base64`)

Verifique a versão:
```bash
python --version