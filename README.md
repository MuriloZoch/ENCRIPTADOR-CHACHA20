# Encriptador ChaCha20

Implementação da cifra de fluxo **ChaCha20** ([RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)) em Python puro, sem bibliotecas de criptografia. O programa cifra e decifra arquivos de qualquer tipo, cifra frases no terminal e valida a implementação com os vetores de teste oficiais da RFC.

---

## Funcionalidades

- Cifra e decifra arquivos de qualquer tipo (texto, imagem, binários)
- Três variantes: **ChaCha8**, **ChaCha12** e **ChaCha20**
- Chave de 256 bits gerada por arquivo e guardada em um chaveiro local
- Nonce aleatório a cada cifragem, gravado no cabeçalho do arquivo cifrado
- Modo de teste para cifrar e decifrar frases no terminal
- Testes automáticos com os vetores oficiais da RFC 8439
- Tratamento de erros (arquivo inexistente, opção inválida, arquivo corrompido, chave ausente)

## Requisitos

- Python **3.9** ou superior
- Nenhuma dependência externa: apenas os módulos padrão `abc` e `secrets`

## Como usar

Clone o repositório e execute o programa **a partir da pasta do projeto**:

```bash
git clone <url-do-repositorio>
cd <pasta-do-repositorio>
python ENCRIPTADOR.py
```

O menu inicial oferece quatro opções:

```
CRIPTOGRAFAR [c] || DESCRIPTOGRAFAR [d] || TESTE [t] || TESTE RFC [r]
```

| Opção | O que faz |
| --- | --- |
| `c` | Cifra um arquivo e gera `<nome>.enc`. Pede o nome do arquivo e a variante (1, 2 ou 3). |
| `d` | Decifra um `.enc` e gera `decifrado_<nome>`. A variante e o nonce são lidos do próprio arquivo. |
| `t` | Cifra uma frase digitada, mostra o resultado em hexadecimal e decifra em seguida. |
| `r` | Roda os vetores de teste da RFC 8439 e mostra `[OK]` ou `[FALHOU]` para cada um. |

> Os arquivos são lidos e gravados na pasta de onde o programa é executado.

### Exemplo

```text
$ python ENCRIPTADOR.py
CRIPTOGRAFAR [c] || DESCRIPTOGRAFAR [d] || TESTE [t] || TESTE RFC [r]
c
DIGITE O NOME DO ARQUIVO: exemplos/imagem_gradiente.png
QUAL ChaCha UTILIZAR:
1-ChaCha8
2-ChaCha12
3-ChaCha20
3
```

Isso gera `exemplos/imagem_gradiente.png.enc`. Em outra execução, a opção `d` com esse arquivo gera `decifrado_...` idêntico ao original.

## Como o ChaCha20 funciona

O ChaCha20 gera uma sequência de bytes pseudoaleatória (o **keystream**) e combina cada byte da mensagem com um byte do keystream usando **XOR**. Como `(M ⊕ K) ⊕ K = M`, a mesma operação cifra e decifra.

Para gerar cada bloco de 64 bytes de keystream:

1. **Monta uma matriz 4×4** de palavras de 32 bits:

   ```
   ┌────────────┬────────────┬────────────┬────────────┐
   │ constante  │ constante  │ constante  │ constante  │  "expand 32-byte k"
   ├────────────┼────────────┼────────────┼────────────┤
   │ chave[0]   │ chave[1]   │ chave[2]   │ chave[3]   │
   ├────────────┼────────────┼────────────┼────────────┤
   │ chave[4]   │ chave[5]   │ chave[6]   │ chave[7]   │
   ├────────────┼────────────┼────────────┼────────────┤
   │ contador   │ nonce[0]   │ nonce[1]   │ nonce[2]   │
   └────────────┴────────────┴────────────┴────────────┘
   ```

2. **Embaralha** a matriz com 20 rodadas (10 de colunas e 10 de diagonais). Cada rodada aplica o *quarter round*, que usa apenas soma, XOR e rotação de bits (ARX).
3. **Soma a matriz original** à embaralhada (sem isso, as rodadas poderiam ser desfeitas).
4. **Converte** as 16 palavras em 64 bytes (little-endian).

Para mensagens maiores, o contador é incrementado a cada bloco.

## Formato do arquivo `.enc`

```
┌──────────┬───────────┬─────────────────────┐
│ variante │ nonce     │ texto cifrado       │
│ 1 byte   │ 12 bytes  │ restante do arquivo │
└──────────┴───────────┴─────────────────────┘
```

- **variante:** `1` = ChaCha8, `2` = ChaCha12, `3` = ChaCha20
- **nonce:** aleatório, novo a cada cifragem

Variante e nonce não são segredos: ficam no arquivo para que a decifração consiga reconstruir o keystream. Toda a segurança depende da chave.

## O chaveiro

Na primeira cifragem, o programa cria o arquivo `chaveiro` na pasta de execução. Cada linha guarda uma chave:

```
nome_do_arquivo:chave_em_hexadecimal
```

- Cada arquivo recebe sua própria chave de 256 bits.
- Cifrar de novo um arquivo com o mesmo nome reaproveita a chave, com um nonce novo.
- **Sem o chaveiro, os arquivos `.enc` não podem ser decifrados**, e quem tiver acesso a ele decifra todos.
- Não renomeie os `.enc`: a chave é buscada pelo nome do arquivo original.

> Adicione `chaveiro` e `*.enc` ao seu `.gitignore` para não publicar suas chaves.

## Estrutura do código

```
CifraDeFluxo (abstrata)
│   cifrar() / decifrar()   → XOR da mensagem com o keystream, em blocos de 64 bytes
│   gerar_bloco()           → abstrato
│
└── ChaCha (abstrata)
    │   matriz()            → monta o estado 4×4
    │   rotate()            → rotação de 32 bits
    │   quarter_round()     → soma, XOR e rotação em 4 palavras
    │   bloco()             → rodadas + soma do estado original
    │   rodadas()           → abstrato
    │
    ├── ChaCha8   (8 rodadas)
    ├── ChaCha12  (12 rodadas)
    └── ChaCha20  (20 rodadas)

Chaveiro                    → carrega, salva, busca e gera chaves (dicionário + arquivo)
```

- **Herança:** a lógica de XOR fica em `CifraDeFluxo` e é reaproveitada por todas as variantes.
- **Polimorfismo:** a variante escolhida vem de um dicionário `{1: ChaCha8, 2: ChaCha12, 3: ChaCha20}`, e o restante do programa usa o objeto sem saber qual variante é.
- **Classes abstratas:** `CifraDeFluxo` e `ChaCha` não podem ser instanciadas; cada variante é obrigada a definir seu número de rodadas.

## Testes

A opção `r` executa os vetores de teste da RFC 8439:

| Teste | Seção da RFC |
| --- | --- |
| Quarter round | 2.1.1 |
| Bloco de keystream | 2.3.2 |
| Cifra completa (mensagem de 114 bytes) | 2.4.2 |

Decifrar e recuperar a mensagem original **não** prova que a cifra está correta, porque o XOR se desfaz mesmo com um keystream errado. Por isso a implementação é comparada com as saídas oficiais da RFC, byte a byte.

A pasta `exemplos/` traz arquivos para testar a cifragem de arquivos:

| Arquivo | Caso testado |
| --- | --- |
| `texto_curto.txt` | mensagem menor que um bloco |
| `texto_acentos.txt` | vários blocos, acentos e caracteres especiais |
| `exatos_64_bytes.txt` | exatamente um bloco |
| `exatos_65_bytes.txt` | um bloco + 1 byte |
| `vazio.txt` | arquivo vazio |
| `notas.csv` | dados tabulares |
| `imagem_gradiente.png` | imagem |
| `binario_1MB.bin` | arquivo grande |

## Limitações

- O ChaCha20 sozinho **não detecta alterações** no arquivo cifrado. Em uso real, ele é combinado com o autenticador Poly1305 (ChaCha20-Poly1305).
- O chaveiro é salvo **sem proteção**. Gerenciadores reais cifram o próprio chaveiro com uma senha mestra.
- A chave precisa ser compartilhada por um canal seguro; o ChaCha20 não resolve a troca de chaves.
- Por ser em Python puro, é bem mais lento que implementações em C (cerca de 2 a 3 segundos para 1 MB).
