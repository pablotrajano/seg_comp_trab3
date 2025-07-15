# main.py
from keygen import generate_rsa_keys, serialize_key, deserialize_key
from signature import rsa_pss_sign, format_signature
from verification import rsa_pss_verify

# Exibe o menu de opções para o usuário
def exibir_menu():
    print("\n=== MENU ASSINATURA DIGITAL RSA-PSS ===")
    print("1. Gerar par de chaves")
    print("2. Exibir chaves")
    print("3. Assinar uma mensagem")
    print("4. Verificar assinatura")
    print("0. Sair")
    return input("Escolha uma opção: ")

def main():
    # Inicializa variáveis globais que armazenarão chaves, assinatura e mensagem
    public_key = None
    private_key = None
    formatted_signature = None
    mensagem_assinada = None

    while True:
        opcao = exibir_menu()

        if opcao == "1":
            # Gera um par de chaves RSA (pública e privada)
            public_key, private_key = generate_rsa_keys()
            print("[✓] Chaves RSA geradas com sucesso.")

        elif opcao == "2":
            # Exibe as chaves codificadas em Base64, com delimitadores estilo PEM
            if public_key and private_key:
                pub_pem = serialize_key(public_key, "PUBLIC")
                priv_pem = serialize_key(private_key, "PRIVATE")
                print("\nChave Pública:\n", pub_pem)
                print("\nChave Privada:\n", priv_pem)
            else:
                print("⚠️ Nenhuma chave gerada ainda.")

        elif opcao == "3":
            if not private_key:
                print("⚠️ Gere as chaves primeiro (opção 1).")
                continue

            # Solicita a mensagem a ser assinada
            mensagem_assinada = input("Digite a mensagem a ser assinada: ").strip()

            # Calcula o tamanho do bloco de assinatura com base no tamanho de n
            em_len = (public_key[0].bit_length() + 7) // 8

            # Assina a mensagem com a chave privada usando RSA-PSS
            assinatura = rsa_pss_sign(mensagem_assinada, private_key, em_len)

            # Codifica a assinatura em Base64
            formatted_signature = format_signature(assinatura, em_len)
            print("\nAssinatura (Base64):\n", formatted_signature)

        elif opcao == "4":
            if not public_key or not formatted_signature or not mensagem_assinada:
                print("⚠️ É necessário assinar uma mensagem antes (opção 3).")
                continue

            print("⚠️ A verificação só será válida se a mensagem for idêntica à original.")
            usar_mesma = input("Usar a mesma mensagem assinada anteriormente? (s/n): ").strip().lower()
            if usar_mesma == "s":
                mensagem_verificada = mensagem_assinada
            else:
                mensagem_verificada = input("Digite a mensagem para verificar a assinatura: ").strip()

            em_len = (public_key[0].bit_length() + 7) // 8

            # Verifica se a assinatura é válida para a mensagem
            valido = rsa_pss_verify(mensagem_verificada, formatted_signature, public_key, em_len)
            print("✅ Assinatura válida!" if valido else "❌ Assinatura inválida.")

        elif opcao == "0":
            print("Saindo...")
            break

        else:
            print("Opção inválida. Tente novamente.")

if __name__ == "__main__":
    main()
