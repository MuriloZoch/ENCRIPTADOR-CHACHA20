from abc import ABC, abstractmethod
import secrets

class CifraDeFluxo(ABC):
    @abstractmethod # OBRIGA AS CLASSES FILHAS A IMPLEMENTAR O METODO
    def gerar_bloco(self, contador):
        pass

    def cifrar(self, mensagem, contador=1): #SEPARA A MENSAGEM EM PEDAÇOS DE 64 BYTES E FAZ XOR DE CADA PEDAÇO COM UM BLOCO DO KEYSTREAM
        resultado = b""

        for i in range(0, len(mensagem), 64):
            x = self.gerar_bloco(contador)
            pedaco = bytearray(mensagem[i:i+64])
            for j in range(len(pedaco)):
                pedaco[j] ^= x[j]

            resultado = resultado + pedaco
            contador += 1

        return resultado

    def decifrar(self, mensagem, contador=1): #PARA DECIFRAR EM ChaCha20 BASTA PASSAR PELA MESMA CIFRA DE ENCRIPTAÇÃO
        return self.cifrar(mensagem, contador)

class ChaCha(CifraDeFluxo):
    def __init__(self, k, n): #GUARDA A CHAVE E O NONCE NO OBJETO
        super().__init__()
        self.key = k
        self.nonce = n

    @abstractmethod
    def rodadas(self): #O NUMERO DE RODADAS É DEFINIDO POR CADA VARIANTE
        pass

    def matriz(self, contador):
        m = []

        # CONSTANTES DA MATRIZ

        m.append(0x61707865)
        m.append(0x3320646E)
        m.append(0x79622D32)
        m.append(0x6B206574)

        # CHAVE

        for i in range(0, 32, 4): #SEPARA A CHAVE EM BLOCOS DE 4 BYTES E ADICIONA NA MATRIZ
            m.append(int.from_bytes(self.key[i:i+4], "little"))

        # CONTADOR

        m.append(contador) #ADICIONA O CONTADOR

        # NONCE

        for i in range(0, 12, 4): #SEPARA O NONCE EM BLOCOS DE 4 BYTES E ADICIONA NA MATRIZ
            m.append(int.from_bytes(self.nonce[i:i+4], "little"))

        return m

    def rotate(self, bits, n): #DEFINE O METODO DE ROTACAO DOS BITS
        return ((bits << n) & 0xFFFFFFFF) | (bits >> (32 - n))

    def quarter_round(self, estado, a, b, c, d): #DEFINE O METODO DO QUARTER ROUND QUE USA ROTATE, SOMA E XOR
        estado[a] += estado[b]
        estado[a] &= 0xFFFFFFFF
        estado[d] ^= estado[a]
        estado[d] = self.rotate(estado[d], 16)

        estado[c] += estado[d]
        estado[c] &= 0xFFFFFFFF
        estado[b] ^= estado[c]
        estado[b] = self.rotate(estado[b], 12)

        estado[a] += estado[b]
        estado[a] &= 0xFFFFFFFF
        estado[d] ^= estado[a]
        estado[d] = self.rotate(estado[d], 8)

        estado[c] += estado[d]
        estado[c] &= 0xFFFFFFFF
        estado[b] ^= estado[c]
        estado[b] = self.rotate(estado[b], 7)

    def bloco(self, estado): 
        copia = estado.copy()

        #APLICA O QUARTER ROUND EM TODAS AS  COLUNAS E DIAGONAIS DA MATRIZ
        for i in range(self.rodadas()//2): #CADA VOLTA FAZ 2 RODADAS (COLUNAS E DIAGONAIS)
            # COLUNAS
            self.quarter_round(copia, 0, 4, 8, 12)
            self.quarter_round(copia, 1, 5, 9, 13)
            self.quarter_round(copia, 2, 6, 10, 14)
            self.quarter_round(copia, 3, 7, 11, 15)

            #DIAGONAIS
            self.quarter_round(copia, 0, 5, 10, 15)
            self.quarter_round(copia, 1, 6, 11, 12)
            self.quarter_round(copia, 2, 7, 8, 13)
            self.quarter_round(copia, 3, 4, 9, 14)

        x = b""
        for i in range(16): # SOMA A MATRIZ ORIGINAL COM SUA VERSÃO EMBARALHADA
            copia[i] += estado[i]
            copia[i] &= 0xFFFFFFFF #COMO PYTHON NÃO TEM UM LIMITE DE INT &0xFFFFFFFF CORTA O NUMERO NOVO PARA ELE MANTER COM O MESMO NUMERO DE BITS
            x = x + copia[i].to_bytes(4, "little")

        return x

    def gerar_bloco(self, contador): #MONTA A MATRIZ E GERA O KEYSTREAM
        return self.bloco(self.matriz(contador))

#VARIANTES: SÓ MUDAM O NÚMERO DE RODADAS
class ChaCha8(ChaCha):
    def rodadas(self):
        return 8

class ChaCha12(ChaCha):
    def rodadas(self):
        return 12

class ChaCha20(ChaCha):
    def rodadas(self):
        return 20

class Chaveiro:
    def __init__(self):
        self.chaves = {}
        self.carregar()

    def carregar(self) : #LE O ARQUIVO CHAVEIRO E CARREGA AS CHAVES NO DICIONARIO
        try:
            with open('chaveiro', 'r') as f:
                for linha in f:
                    linha = linha.strip()
                    if not linha: continue
                    nome, hexa = linha.rsplit(":", 1)
                    self.chaves[nome] = bytes.fromhex(hexa)
        except FileNotFoundError:
            pass

    def salvar(self): #SALVA O NOME E A CHAVE UTILIZADA NO ARQUIVO CHAVEIRO
        with open('chaveiro', 'w') as f:
            for nome, chave in self.chaves.items():
                f.write(nome + ":" + chave.hex() + "\n")

    def buscar(self, nome): #PROCURA A CHAVE PELO NOME NO DICIONARIO 'CHAVES'
        return self.chaves.get(nome)

    def adicionar(self, nome): #DEVOLVE A CHAVE SE ELA JÁ EXISTIR; CASO CONTRARIO GERA UMA NOVA, GUARDA E SALVA NO ARQUIVO
        try:
            return self.chaves[nome]
        except KeyError:
            chave = secrets.token_bytes(32)
            self.chaves[nome] = chave
            self.salvar()
            return chave

def main(): #ROTEIRO BASICO PARA UTILIZAÇÃO DO ALGORITMO
    escolha = input("CRIPTOGRAFAR [c] || DESCRIPTOGRAFAR [d] || TESTE [t] || TESTE RFC [r]\n")
    
    cifras = {1: ChaCha8, 2: ChaCha12, 3: ChaCha20} #ASSOCIA CADA OPÇÃO DO MENU A UMA CLASSE DE CIFRA
    chaveiro = Chaveiro()
    
    if (escolha == 'c' or escolha == 'C'):
        arquivo = input("DIGITE O NOME DO ARQUIVO: ")
        try:
            with open(arquivo, 'rb') as f:
                mensagem = f.read()
        except FileNotFoundError:
            print("ARQUIVO NAO ENCONTRADO")
            return
        nonce = secrets.token_bytes(12)
        try:
            metodo = int(input("QUAL ChaCha UTILIZAR:\n1-ChaCha8\n2-ChaCha12\n3-ChaCha20\n"))
        except ValueError:
            print("ESCOLHA INVALIDA")
            return
        if metodo not in cifras:
            print("ESCOLHA INVALIDA")
            return
    elif (escolha == 'd' or escolha == 'D'):
        arquivo = input("DIGITE O NOME DO ARQUIVO: ")
        try:
            with open(arquivo, 'rb') as f:
                mensagem = f.read()
        except FileNotFoundError:
            print("ARQUIVO NAO ENCONTRADO")
            return
        if len(mensagem) < 13:
            print("ARQUIVO INVALIDO")
            return
        metodo = mensagem[0]
        if metodo not in cifras:
            print("ARQUIVO INVALIDO")
            return
        nonce = mensagem[1:13]
        mensagem = mensagem[13:]
    elif (escolha == 't' or escolha == 'T'):
        try:
            metodo = int(input("QUAL ChaCha UTILIZAR:\n1-ChaCha8\n2-ChaCha12\n3-ChaCha20\n"))
        except ValueError:
            print("ESCOLHA INVALIDA")
            return
        if metodo not in cifras:
            print("ESCOLHA INVALIDA")
            return
        frase = (input("DIGITE A FRASE A SER ENCRIPTADA:\n").encode())
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        cifra = cifras[metodo](key, nonce)
        print("CIFRANDO:\n")
        frase = cifra.cifrar(frase)
        print(frase.hex(" "))
        print("\nDECIFRANDO:\n")
        frase = cifra.decifrar(frase)
        print(frase.decode())
    elif (escolha == 'r' or escolha == 'R'):
        print("TESTE RFC 8439\nA RFC 8439 é o documento oficial que define o ChaCha20.\n" \
        "Ela traz exemplos com entradas fixas (chave, nonce e contador) e o resultado exato que uma implementação correta deve produzir.\n" \
        "Este teste roda o programa com essas mesmas entradas e compara a saída com a resposta oficial, byte a byte.\n")
        # TESTE DE QUARTER ROUND
        key = bytes(32)
        nonce = bytes(12)
        cifra = ChaCha20(key, nonce)
        teste = [0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567]
        prova = [0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb]
        print("-TESTE QUARTER ROUND-\n")
        print("ENTRADA:", [format(x, "08x") for x in teste])
        cifra.quarter_round(teste, 0, 1, 2, 3)
        print("SAIDA ESPERADA: ", [format(x, "08x") for x in prova])
        print("SAIDA OBTIDA: ", [format(x, "08x") for x in teste])
        if (prova == teste):
            print("[OK]\n")
        else:
            print("[FALHOU]\n")
        key = bytes(range(32))
        nonce = bytes.fromhex("00 00 00 09 00 00 00 4a 00 00 00 00")
        cifra = ChaCha20(key, nonce)
        teste = cifra.gerar_bloco(1)
        prova = ("10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4 c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c"
        " 4e d2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2 b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e")
        prova = bytes.fromhex(prova)
        # TESTE DE BLOCOS
        print("-TESTE DE BLOCOS-\n")
        print("ENTRADA:")
        print("nonce: ", nonce.hex(" "))
        print("key: ", key.hex(" "))
        print("SAIDA ESPERADA: ", prova.hex(" "))
        print("SAIDA OBTIDA: ", teste.hex(" "))
        if (prova == teste):
            print("[OK]\n")
        else:
            print("[FALHOU]\n")

        # TESTE DE CIFRA
        key = bytes(range(32))
        nonce = bytes.fromhex("00 00 00 00 00 00 00 4a 00 00 00 00")
        mensagem = ("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.").encode()
        cifra = ChaCha20(key, nonce)
        teste = cifra.cifrar(mensagem)
        prova = ("6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81 e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57 16 39 d6 "
        "24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8 07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e 52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36 5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42 87 4d")
        prova = bytes.fromhex(prova)
        print("-TESTE DE CIFRA-\n")
        print("ENTRADA: ", mensagem.decode())
        print("SAIDA ESPERADA: ", prova.hex(" "))
        print("SAIDA OBTIDA: ", teste.hex(" "))
        if (prova == teste):
            print("[OK]\n")
        else:
            print("[FALHOU]\n")

    else:
        print("OPCAO INVALIDA")
        return

    if (escolha == 'c' or escolha == 'C'):
        key = chaveiro.adicionar(arquivo)
        cifra = cifras[metodo](key, nonce)
        mensagem = cifra.cifrar(mensagem)
        with open(arquivo + ".enc", 'wb') as f: #CRIA O ARQUIVO ENCRIPTADO COM A EXTENSÃO '.ENC' E ADICIONA O METODO E O NONCE NO CABEÇALHO
            f.write(bytes([metodo]))
            f.write(nonce)
            f.write(mensagem)

    elif (escolha == 'd' or escolha == 'D'):
        nome_original = arquivo.removesuffix(".enc")
        key = chaveiro.buscar(nome_original)
        if key is None:
            print("CHAVE NAO ENCONTRADA")
            return
        cifra = cifras[metodo](key, nonce)
        mensagem = cifra.decifrar(mensagem)
        saida = "decifrado_" + nome_original
        with open(saida, 'wb') as f:
            f.write(mensagem)

main()