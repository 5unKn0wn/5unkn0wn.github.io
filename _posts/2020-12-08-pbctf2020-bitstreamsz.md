---
layout: post
title: Codegate 2022 Final - AESMaster (Reversing)
tags: CTF
---

# Reversing - AESMaster

# TL;DR

- 문제의 목적은 $AES(k, p) = p$ 인 $k$를 찾는 일종의 AES fixed point 문제
- UPX 언패커를 통해 언패킹 했을 때와 실제 실행 압축이 풀릴 때 AES의 sbox가 달라짐
- 달라진 sbox는 선형적이기 때문에 AES 전체 과정을 하나의 선형 함수로 볼 수 있음
- 따라서 연립방정식을 세워 fixed point 문제 해결

# Intrduction

AESMaster 바이너리는 UPX로 패킹된 32비트 PE 형태의 바이너리이다. UPX 언패커를 다운로드 받아 패킹을 해제한 뒤, 바이너리를 분석해보면 바이너리가 수행하는 행위 자체는 간단하다.

이용자에게 32바이트 hex 인코딩된 인풋을 입력받고, 이를 디코딩하여 AES의 키로 사용한다. 이후, `codegate2022{xx}` 라는 값을 암호화한 값이 `codegate2022{xx}` 그대로 나온다면 입력한 키를 플래그로 출력해준다.

바이너리 자체에는 아무런 난독화가 적용되어있지 않기 때문에 분석 자체는 간단한 편이다. AES의 동작 구조를 이해하고 있다면 암호화 함수가 수행하는 동작을 분석하여 AES임을 인지하고, 이후부터는 바이너리 분석을 통해 얻어낼 수 있는 정보는 크게 없다.

이제 문제를 풀기 위해서는 어떤 키를 입력으로 넣어야 AES 함수의 입력과 출력이 같은 값이 나오는지를 찾아야 한다. 참고로 어떤 함수 $f$가 존재할 때, $f(x) = x$ 와 같이 입력과 출력이 같아지는 점 $x$를 [fixed point](https://ko.wikipedia.org/wiki/%EA%B3%A0%EC%A0%95%EC%A0%90) (고정점) 라고 한다.

# Find backdoor’ed S-BOX

일반적으로 AES의 입력과 출력이 같게 만들어주는 키는 존재하지 않는다. (혹은 아직 발견되지 않았다.)

이처럼 아직 발견되지 않았거나 불가능하다고 느껴지는 행위를 리버싱 문제에서 요구한다면, 이는 바이너리 상에서 구현한 알고리즘이 원본 알고리즘과 다르거나, 특수한 상황에서만 발현되는 백도어 형태의 코드가 존재해 해당 상황에서만 바이너리가 요구하는 조건을 만족할 수 있을 확률이 높다.

비슷한 형태의 문제로 2020년 hxpctf에 출제되었던 md15 문제를 예로들 수 있다.

md5 해시를 이용하여 여러 개의 아웃풋이 있고, 아웃풋의 입력 간 차분 (difference)이 주어졌을 때 입력 값을 구해야하는 컨셉의 문제이다. 물론, 이 역시 알려진 해결법이 없는 문제이다.

이 문제 또한 elf 바이너리에서 `__libc_csu_init` 함수가 변조되어 백도어가 존재하는 형태의 문제였으며, 실제로는 md5 해시의 전체 라운드 수가 1/4로 줄어들었을 때 평문을 복구하는 형태의 문제였다.

자세한 라이트업은 pasten 팀의 [라이트업](https://github.com/oranav/ctf-writeups/tree/master/36c3/md15)을 참고.

따라서 AESMaster 문제도 AES 로직이 변경되었거나, 백도어가 있다고 판단하였다.

먼저 upx가 언패킹된 바이너리에서 직접 AES 함수를 실행해보면 원본 AES 함수와 똑같이 동작하기 때문에 AES 로직이 변경되지는 않았다고 판단하였다. 그렇다면 바이너리 내 어딘가에 백도어가 있다고 판단할 수 있는데, 언패킹된 바이너리 내에 별도의 백도어 코드는 볼 수 없었다.

이 때부터 upx를 의심하기 시작했고, upx로 패킹되어있는 원본 바이너리를 직접 디버깅해서 AES 함수를 실행해보니 원본 암호화와 다른 방식으로 동작하는 것을 확인하였다.

![언패커로 언패킹하지 않고 실행 압축으로 해제했을 때 암호문 (input = “0” * 32)](/images/codegate2022-final-aesmaster/Screen_Shot_2022-11-10_at_10.40.46_PM.png)

언패커로 언패킹하지 않고 실행 압축으로 해제했을 때 암호문 (input = “0” * 32)

![언패커로 언패킹했을 때 암호문 (input = “0” * 32)](/images/codegate2022-final-aesmaster/Screen_Shot_2022-11-10_at_10.39.59_PM.png)

언패커로 언패킹했을 때 암호문 (input = “0” * 32)

이후 바이너리를 분석해보니 AES 암호화에 사용되는 테이블 중 S-BOX가 변경되어있음을 확인하였다.

![변조된 S-BOX](/images/codegate2022-final-aesmaster/Untitled.png)

변조된 S-BOX

![원본 S-BOX](/images/codegate2022-final-aesmaster/Untitled%201.png)

원본 S-BOX

따라서 이 문제는 원본 AES에서 S-BOX가 다른 값으로 변경되었을 때 AES를 공격하는 문제로 볼 수 있게 된다.

# Vulnerable S-BOX

AES의 S-BOX가 변조되었을 때의 취약성을 이해하려면 먼저 AES 암호화에서 S-BOX가 어떤 역할을 지니는지 이해하는 것이 중요하다. AES 암호화의 내부 구조에 대해서 잘 알지 못한다면, [드림핵 강의](https://dreamhack.io/lecture/courses/73)를 먼저 이해하길 추천한다.

AES 암호화의 기본 구조는 SPN (Substitute-Permutation-Network)의 형태를 띈다. 즉 치환와 순열의 구조를 갖는 암호라는 의미인데, AES 내부 구조에서 sub bytes 과정이 치환을, shift rows와 mix columns 과정이 순열의 역할을 한다. **AES에서 치환이 중요한 이유는 선형적인 암호화 과정을 비선형적으로 만들어준다는 점이다.** 

shift rows와 mix columns 과정은 선형적인 연산이기 때문에 치환 과정이 없다면 행렬이나 기타 선형적인 연산으로 변형하여 암호문을 복구하거나 키를 복구하는 형태의 공격이 가능해진다. 따라서 매 라운드마다 비선형적인 연산인 치환을 수행하여 선형적인 연산으로 암호를 공격하지 못하도록 하는데에 목적이 있다. 

S-BOX는 sub bytes에서 치환을 하기 위한 테이블로 사용되어, sbox[0] = 0x63, sbox[1] = 0x7c, … 등으로 1바이트 입력을 넣었을 때 무작위 (에 가까운) 값 새로운 1 바이트로 치환하는 역할을 한다. 만약 S-BOX가 올바르게 생성되지 않는다면 S-BOX 식을 선형에 가깝게 근사하여 공격하는 linear cryptanalysis나 기타 공격에 취약해지기 때문에 이를 올바르게 선택하는 것은 아주 중요하다.

이제 문제에서 주어진 S-BOX를 분석해보자.

```python
sbox = (76, 81, 118, 107, 56, 37, 2, 31, 164, 185, 158, 131, 208, 205, 234, 247, 135, 154, 189, 160, 243, 238, 201, 212, 111, 114, 85, 72, 27, 6, 33, 60, 193, 220, 251, 230, 181, 168, 143, 146, 41, 52, 19, 14, 93, 64, 103, 122, 10, 23, 48, 45, 126, 99, 68, 89, 226, 255, 216, 197, 150, 139, 172, 177, 77, 80, 119, 106, 57, 36, 3, 30, 165, 184, 159, 130, 209, 204, 235, 246, 134, 155, 188, 161, 242, 239, 200, 213, 110, 115, 84, 73, 26, 7, 32, 61, 192, 221, 250, 231, 180, 169, 142, 147, 40, 53, 18, 15, 92, 65, 102, 123, 11, 22, 49, 44, 127, 98, 69, 88, 227, 254, 217, 196, 151, 138, 173, 176, 78, 83, 116, 105, 58, 39, 0, 29, 166, 187, 156, 129, 210, 207, 232, 245, 133, 152, 191, 162, 241, 236, 203, 214, 109, 112, 87, 74, 25, 4, 35, 62, 195, 222, 249, 228, 183, 170, 141, 144, 43, 54, 17, 12, 95, 66, 101, 120, 8, 21, 50, 47, 124, 97, 70, 91, 224, 253, 218, 199, 148, 137, 174, 179, 79, 82, 117, 104, 59, 38, 1, 28, 167, 186, 157, 128, 211, 206, 233, 244, 132, 153, 190, 163, 240, 237, 202, 215, 108, 113, 86, 75, 24, 5, 34, 63, 194, 223, 248, 229, 182, 171, 140, 145, 42, 55, 16, 13, 94, 67, 100, 121, 9, 20, 51, 46, 125, 96, 71, 90, 225, 252, 219, 198, 149, 136, 175, 178)
```

합리적인 의심으로.. sbox를 취약하게 변형한다면, 제일 유력한 방법은 sbox 자체를 선형적으로 만드는 케이스가 존재한다. 선형 함수의 특징은 다음 두 특징이 있는데,

$$
f(x + y) = f(x) + f(y)\\
af(x) = f(ax)
$$

이 중 첫 번째 특성을 이용하여 이를 확인하였다.

```python
for i in range(256):
    for j in range(256):
        assert sbox[i] ^ sbox[j] ^ sbox[0] == sbox[i ^ j]
```

![sbox의 선형성 확인](/images/codegate2022-final-aesmaster/Untitled%202.png)

단 하나의 assert도 걸리지 않은 것을 확인할 수 있다. 이 때 AES 에서 덧셈과 뺄셈은 bitwise xor로 이루어지기 때문에 이에 유의해야 한다. 

자 기존에 AES에서 치환의 목적은 비선형성을 추가하기 위함이라고 했는데, 수정된 S-BOX에 의해 AES의 전체 과정이 선형적이게 되었다. 위 수식과 같은 원리로 AES의 선형성에 대해서도 검사해볼 수 있다.

```python
s_box = (76, 81, 118, 107, 56, 37, 2, 31, 164, 185, 158, 131, 208, 205, 234, 247, 135, 154, 189, 160, 243, 238, 201, 212, 111, 114, 85, 72, 27, 6, 33, 60, 193, 220, 251, 230, 181, 168, 143, 146, 41, 52, 19, 14, 93, 64, 103, 122, 10, 23, 48, 45, 126, 99, 68, 89, 226, 255, 216, 197, 150, 139, 172, 177, 77, 80, 119, 106, 57, 36, 3, 30, 165, 184, 159, 130, 209, 204, 235, 246, 134, 155, 188, 161, 242, 239, 200, 213, 110, 115, 84, 73, 26, 7, 32, 61, 192, 221, 250, 231, 180, 169, 142, 147, 40, 53, 18, 15, 92, 65, 102, 123, 11, 22, 49, 44, 127, 98, 69, 88, 227, 254, 217, 196, 151, 138, 173, 176, 78, 83, 116, 105, 58, 39, 0, 29, 166, 187, 156, 129, 210, 207, 232, 245, 133, 152, 191, 162, 241, 236, 203, 214, 109, 112, 87, 74, 25, 4, 35, 62, 195, 222, 249, 228, 183, 170, 141, 144, 43, 54, 17, 12, 95, 66, 101, 120, 8, 21, 50, 47, 124, 97, 70, 91, 224, 253, 218, 199, 148, 137, 174, 179, 79, 82, 117, 104, 59, 38, 1, 28, 167, 186, 157, 128, 211, 206, 233, 244, 132, 153, 190, 163, 240, 237, 202, 215, 108, 113, 86, 75, 24, 5, 34, 63, 194, 223, 248, 229, 182, 171, 140, 145, 42, 55, 16, 13, 94, 67, 100, 121, 9, 20, 51, 46, 125, 96, 71, 90, 225, 252, 219, 198, 149, 136, 175, 178)

def sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box[s[i][j]]

def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]

def add_round_key(s, k):
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]

# learned from https://web.archive.org/web/20100626212235/http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)

def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])

r_con = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)

def bytes2matrix(text):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    return bytes(sum(matrix, []))

def xor_bytes(a, b):
    """ Returns a new byte array with the elements xor'ed. """
    return bytes(i^j for i, j in zip(a, b))

class AES:
    """
    Class for AES-128 encryption with CBC mode and PKCS#7.
    This is a raw implementation of AES, without key stretching or IV
    management. Unless you need that, please use `encrypt` and `decrypt`.
    """
    rounds_by_key_size = {16: 10, 24: 12, 32: 14}
    def __init__(self, master_key):
        """
        Initializes the object with a given key.
        """
        assert len(master_key) in AES.rounds_by_key_size
        self.n_rounds = AES.rounds_by_key_size[len(master_key)]
        self._key_matrices = self._expand_key(master_key)

    def _expand_key(self, master_key):
        """
        Expands and returns a list of key matrices for the given master_key.
        """
        # Initialize round keys with raw key material.
        key_columns = bytes2matrix(master_key)
        iteration_size = len(master_key) // 4

        i = 1
        while len(key_columns) < (self.n_rounds + 1) * 4:
            # Copy previous word.
            word = list(key_columns[-1])

            # Perform schedule_core once every "row".
            if len(key_columns) % iteration_size == 0:
                # Circular shift.
                word.append(word.pop(0))
                # Map to S-BOX.
                word = [s_box[b] for b in word]
                # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
                word[0] ^= r_con[i]
                i += 1
            elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
                # Run word through S-box in the fourth iteration when using a
                # 256-bit key.
                word = [s_box[b] for b in word]

            # XOR with equivalent word from previous iteration.
            word = xor_bytes(word, key_columns[-iteration_size])
            key_columns.append(word)

        # Group key words in 4x4 byte matrices.
        return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]

    def encrypt_block(self, plaintext):
        """
        Encrypts a single block of 16 byte long plaintext.
        """
        assert len(plaintext) == 16

        plain_state = bytes2matrix(plaintext)

        add_round_key(plain_state, self._key_matrices[0])

        for i in range(1, self.n_rounds):
            sub_bytes(plain_state)
            shift_rows(plain_state)
            mix_columns(plain_state)
            add_round_key(plain_state, self._key_matrices[i])

        sub_bytes(plain_state)
        shift_rows(plain_state)
        add_round_key(plain_state, self._key_matrices[-1])

        return matrix2bytes(plain_state)

    def decrypt_block(self, ciphertext):
        """
        Decrypts a single block of 16 byte long ciphertext.
        """
        assert len(ciphertext) == 16

        cipher_state = bytes2matrix(ciphertext)

        add_round_key(cipher_state, self._key_matrices[-1])
        inv_shift_rows(cipher_state)
        inv_sub_bytes(cipher_state)

        for i in range(self.n_rounds - 1, 0, -1):
            add_round_key(cipher_state, self._key_matrices[i])
            inv_mix_columns(cipher_state)
            inv_shift_rows(cipher_state)
            inv_sub_bytes(cipher_state)

        add_round_key(cipher_state, self._key_matrices[0])

        return matrix2bytes(cipher_state)

from pwn import *

k = b"\x00" * 16

aes = AES(k)
ct0 = aes.encrypt_block(b'\x00' * 16)
ct1 = aes.encrypt_block(b'\x01' * 16)
ct2 = aes.encrypt_block(b'\x02' * 16)
ct3 = aes.encrypt_block(b'\x03' * 16)
print(xor(ct0, ct1, ct2) == ct3)
print(1 ^ 2 == 3)
```

![변조된 AES의 선형성 확인](/images/codegate2022-final-aesmaster/Untitled%203.png)

True가 나오는 것을 확인할 수 있다.

즉, 이 문제는 선형적인 AES가 주어졌을 때 $\text{LinearAES}(k, p) = p$를 만족하는 $k$를 구하는 문제로 바뀐다.

# Breaking LinearAES

선형 함수가 주어졌을 때 fixed point를 구해야하는 문제는 과거 다양한 ctf에 출제된 적 있다. 이런 류의 문제에 관심있다면 0ctf 2020 - fixedpoint, [포카전 2020 - fixed point revenge](https://rbtree.blog/posts/2020-09-20-poka-science-war-hacking/) 를 추천한다. 관련 내용은 rbtree 님의 블로그에 잘 정리되어있다 ㅎㅎ

위 두 개의 문제는 CRC 함수에 대한 문제였지만, 이번엔 AES가 되었다. AES라고 크게 다른 점은 없는데, 이미 AES가 선형 함수가 된 이상, 해당 문제를 $GF(2^8)$ 위의 행렬로 표현하는게 가능해진다.

전체적인 아이디어는 AES의 전체 과정을 $GF(2^8)$ 위의 연산으로 변경하고, 키 $k$를 변수로 둔 채 `codegate2022{xx}` 값을 암호화한다. 이러면 해당 평문에 대한 암호문을 획득할 수 있고, 해당 암호문은 키가 변수였기 때문에 상수 값이 아닌 방정식의 꼴로 표현된다.

이 상태에서 16개의 미지수와 16개의 방정식 (암호문 16바이트)이 존재하니 연립방정식을 해결하여 키를 획득할 수 있다.

```python
F.<x> = GF(2^8, "x", modulus=x^8+x^4+x^3+x+1)

def int2el(n):
    return F.fetch_int(n)

def el2int(n):
    return n.integer_representation()

def gadd(a, b):
    return [x + y for x, y in zip(a, b)]

def gmul(a, b):
    return F.fetch_int(a) * b

def substitute(x):
    a = F.fetch_int(29)
    b = F.fetch_int(76)
    return a * x + b

class LinearAES:
    rcon = (0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)
    rcon = [int2el(r) for r in rcon]

    def __init__(self, key):
        self._block_size = 16
        self._round_keys = self._expand_key([k for k in key])
        self._state = []

    def _transpose(self, m):
        return [m[4 * j + i] for i in range(4) for j in range(4)]

    def _expand_key(self, key):
        round_keys = [key]

        for i in range(10):
            round_key = []
            first = round_keys[i][:4]
            last = round_keys[i][-4:]
            last = last[1:] + [last[0]]
            last = [substitute(i) for i in last]

            round_key.extend(gadd(gadd(first, last), [self.rcon[i+1], 0, 0, 0]))
            for j in range(0, 12, 4):
                round_key.extend(gadd(round_key[j:j + 4], round_keys[i][j + 4:j + 8]))
            round_keys.append(round_key)

        for i in range(len(round_keys)):
            round_keys[i] = self._transpose(round_keys[i])

        return round_keys

    def _add_round_key(self, i):
        self._state = gadd(self._round_keys[i], self._state)

    def _mix_columns(self):
        s = [0] * self._block_size
        for i in range(4):
            s[i +  0] = gmul(2, self._state[i]) + gmul(3, self._state[i + 4]) + self._state[i + 8] + self._state[i + 12]
            s[i +  4] = self._state[i] + gmul(2, self._state[i + 4]) + gmul(3, self._state[i + 8]) + self._state[i + 12]
            s[i +  8] = self._state[i] + self._state[i + 4] + gmul(2, self._state[i + 8]) + gmul(3, self._state[i + 12])
            s[i + 12] = gmul(3, self._state[i]) + self._state[i + 4] + self._state[i + 8] + gmul(2, self._state[i + 12])
        self._state = s
        
    def _shift_rows(self):
        self._state = [
            self._state[0], self._state[1], self._state[2], self._state[3],
            self._state[5], self._state[6], self._state[7], self._state[4],
            self._state[10], self._state[11], self._state[8], self._state[9],
            self._state[15], self._state[12], self._state[13], self._state[14]
        ]
        
    def _sub_bytes(self):
        self._state = [substitute(i) for i in self._state]
        
    def _encrypt_block(self):
        self._add_round_key(0)

        for i in range(1, 10):
            self._sub_bytes()
            self._shift_rows()
            self._mix_columns()
            self._add_round_key(i)

        self._sub_bytes()
        self._shift_rows()
        self._add_round_key(10)

    def encrypt(self, plaintext):
        ciphertext = []
        plaintext = [int2el(c) for c in plaintext]
        self._state = self._transpose(plaintext)
        self._encrypt_block()
        ciphertext.extend(self._transpose(self._state))

        return ciphertext

msg = b"codegate2022{xx}"
key = PolynomialRing(F, "k", 16).gens()
aes = LinearAES(key)
ct = aes.encrypt(msg)
eqs = [x - int2el(y) for x, y in zip(ct, msg)]
M, v = Sequence(eqs).coefficient_matrix()
key = vector(M[:, :-1].solve_right(M[:, -1]))
print(f"codegate2022{{{bytes([el2int(i) for i in key]).hex()}}}")
```

![연립방정식을 이용한 키 복구](/images/codegate2022-final-aesmaster/Untitled%204.png)

# Conclusion

블로그를 너무 오래 방치해두기도 했고.. 간만에 재미난 문제를 풀어서 간략하게 라이트업을 써보았습니다. 뒤로갈수록 설명이 조금은 부실해지는 감이 없잖아 있는데, 궁금하거나 이해가 안가는 부분들은 연락주시면 편하게 답변드리겠습니다 ㅎ.ㅎ

원래 영어로 쓸까하다가.. 시간 너무 많이 쏟을거같아서 국문으로만 작성하였으니 외국인 분들은 Google Translator 사용 부탁드립니다 ㅎㅋ