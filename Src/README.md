# RSA 3072 Signature Verification & AES-256-CBC Decryption

RSA 3072 서명 검증 및 AES-256-CBC 복호화 라이브러리 (F/W 포팅용)

## 1. 개요

rsa3072 및 aes256cbc 라이브러리 검증을 위한 통합 테스트 프로그램입니다.

프로그램 실행 시 다음 순서로 테스트를 수행합니다:

**RSA 3072 서명 검증 테스트:**
1. **Static 테스트**: test/ 폴더의 사전 생성된 데이터로 기본 검증
2. **Dynamic 테스트**: OpenSSL로 랜덤 키/서명 생성 후 rsa3072 라이브러리로 검증

**AES-256-CBC 복호화 테스트:**
1. **Dynamic 테스트**: OpenSSL로 암호화 후 aes256cbc 라이브러리로 복호화

각 테스트에서 수행하는 검증:
- RSA: 유효한 서명, 손상된 메시지, 손상된 서명
- AES: 정상 복호화, 잘못된 키, 잘못된 IV, 손상된 암호문

**디렉토리 구조:**
```
Build/
├── make_lib/               # ARM 라이브러리 빌드
│   ├── Makefile.mak        # ARM 빌드 규칙
│   ├── BuildOption.mak     # 컴파일러 옵션
│   ├── Build.bat           # 빌드 스크립트
│   └── BuildProject.bat    # 대화형 빌드 메뉴
└── vs2010/                 # VS2010 테스트 빌드
    ├── C-Encryption.sln
    └── C-Encryption.vcxproj

Src/
├── main.c                  # 통합 테스트 프로그램
├── Makefile                # GCC 테스트 빌드
├── rsa3072/                # RSA 3072 라이브러리
│   ├── rsa3072.h/c         # 서명 검증
│   ├── bn384.h/c           # BigNum 연산 (Montgomery 곱셈)
│   └── sha256.h/c          # SHA-256
├── aes256cbc/              # AES-256-CBC 라이브러리
│   └── aes256cbc.h/c       # 복호화 구현
├── test/                   # Static 테스트 데이터 (RSA용)
├── libssl.lib              # OpenSSL 라이브러리 (MSVC)
├── libcrypto.lib
├── libssl.a                # OpenSSL 라이브러리 (GCC)
└── libcrypto.a
```

## 2. 테스트 준비

### 2.1. RSA 테스트 데이터 파일

| 파일 | 크기 | 설명 |
|------|------|------|
| private.pem | - | RSA 3072 개인키 (PEM 형식) |
| public.pem | - | RSA 3072 공개키 (PEM 형식) |
| public_n.bin | 384 bytes | 공개키 Modulus N (바이너리) |
| message.bin | 16384 bytes | 테스트 메시지 (16 KiB 랜덤 데이터) |
| signature.bin | 384 bytes | message.bin의 RSA-SHA256 서명 |

### 2.2. RSA 테스트 데이터 생성

```bash
# 새 키 쌍 생성 (-F4: 공개 지수 E = 65537)
openssl genrsa -F4 -out test/private.pem 3072
openssl rsa -in test/private.pem -pubout -out test/public.pem

# 공개키 정보 확인 (N, E)
openssl rsa -in test/public.pem -pubin -text -noout

# Modulus N 추출 (바이너리)
openssl rsa -in test/public.pem -pubin -modulus -noout | cut -d= -f2 | xxd -r -p > test/public_n.bin

# 새 메시지 생성 (Linux/Git Bash)
dd if=/dev/urandom of=test/message.bin bs=1024 count=16

# 메시지 서명 (PKCS#1 v1.5 + SHA-256)
openssl dgst -sha256 -sign test/private.pem -out test/signature.bin test/message.bin

# 서명 검증
openssl dgst -sha256 -verify test/public.pem -signature test/signature.bin test/message.bin
```

### 2.3. AES-256-CBC 테스트 (OpenSSL 명령행)

```bash
# 암호화 (no padding, 입력은 16바이트 배수여야 함)
openssl enc -aes-256-cbc -K <hex_key> -iv <hex_iv> -in plaintext.bin -out ciphertext.bin -nopad

# 복호화
openssl enc -d -aes-256-cbc -K <hex_key> -iv <hex_iv> -in ciphertext.bin -out decrypted.bin -nopad
```

### 2.4. OpenSSL 설정 (Windows)

OpenSSL 테스트 빌드에는 OpenSSL 헤더가 필요합니다. Makefile의 `OPENSSL_DIR`을 수정하세요:

```makefile
# Makefile 내 OpenSSL 경로 (설치 위치에 맞게 수정)
OPENSSL_DIR = C:/Program Files (x86)/OpenSSL-Win32
```

## 3. 빌드

### 3.1. GCC 테스트 빌드 (OpenSSL 필요)

```bash
cd Src
make            # 빌드
./openssl_test  # 실행
```

**빌드 타겟:**

| 타겟 | 설명 |
|------|------|
| `make` 또는 `make all` | 통합 테스트 프로그램 빌드 (기본) |
| `make test` | 빌드 후 실행 |
| `make clean` | 빌드 결과물 삭제 |
| `make help` | 도움말 출력 |

**RSA3072 라이브러리:**

| 타겟 | 설명 |
|------|------|
| `make rsa3072` | RSA3072 라이브러리 오브젝트 빌드 |
| `make rsa3072-test` | RSA3072 단독 테스트 빌드 및 실행 |
| `make rsa3072-size` | RSA3072 코드 크기 확인 |
| `make rsa3072-clean` | RSA3072 오브젝트 삭제 |

**AES256CBC 라이브러리:**

| 타겟 | 설명 |
|------|------|
| `make aes256cbc` | AES256CBC 라이브러리 오브젝트 빌드 |
| `make aes256cbc-size` | AES256CBC 코드 크기 확인 |
| `make aes256cbc-clean` | AES256CBC 오브젝트 삭제 |

### 3.2. ARM 라이브러리 빌드 (Cortex-M3)

ARM Compiler 5 (armcc/armar) 기반 정적 라이브러리를 생성합니다.

```bash
cd Build/make_lib
BuildProject.bat        # 대화형 메뉴
# 또는
Build.bat clean          # 전체 클린 빌드
Build.bat clean rsa3072  # rsa3072.lib 만 클린 빌드
Build.bat aes256cbc      # aes256cbc.lib 만 증분 빌드
```

빌드 결과물은 `Build/make_lib/_out/lib/`에 생성됩니다:

```
_out/lib/
├── rsa3072.lib      # RSA 3072 정적 라이브러리
├── rsa3072.h        # Public API 헤더
├── aes256cbc.lib    # AES-256-CBC 정적 라이브러리
└── aes256cbc.h      # Public API 헤더
```

### 3.3. VS2010 테스트 빌드

`Build/vs2010/C-Encryption.sln`을 Visual Studio 2010에서 열고 x64 플랫폼으로 빌드합니다.
OpenSSL-Win64 헤더 경로(`C:\Program Files\OpenSSL-Win64\include`)가 설치되어 있어야 합니다.

## 4. Minimal RSA3072 라이브러리

### 4.1. API

```c
#include "rsa3072.h"

/**
 * RSA 3072 서명 검증
 *
 * @param p_public_n   공개키 Modulus N (384 bytes, big-endian)
 * @param p_message    검증할 메시지
 * @param message_len  메시지 길이
 * @param p_signature  서명 (384 bytes, big-endian)
 * @return             RSA3072_OK(0): 성공, 기타: 실패
 */
int rsa3072_verify(const uint8_t* p_public_n,
                   const uint8_t* p_message,
                   size_t         message_len,
                   const uint8_t* p_signature);
```

### 4.2. 사용 예시

```c
#include "rsa3072.h"

int result = rsa3072_verify(public_n,      /* 384 bytes */
                            message,
                            message_len,
                            signature);    /* 384 bytes */

if (result == RSA3072_OK) {
    /* 서명 검증 성공 */
} else {
    /* 서명 검증 실패 */
}
```

### 4.3. 기술 사양

| 항목 | 값 |
|------|------|
| 키 크기 | RSA 3072-bit |
| 해시 알고리즘 | SHA-256 |
| 패딩 방식 | PKCS#1 v1.5 |
| 공개 지수 (E) | 65537 (0x10001) 고정 |
| 서명 크기 | 384 bytes |

## 5. Minimal AES256CBC 라이브러리

### 5.1. API

```c
#include "aes256cbc.h"

/**
 * AES-256-CBC 복호화 (no padding)
 *
 * @param p_key         암호화 키 (32 bytes)
 * @param p_iv          초기화 벡터 (16 bytes)
 * @param p_ciphertext  암호문 (16바이트 배수)
 * @param len           데이터 길이 (16의 배수)
 * @param p_plaintext   출력 버퍼 (암호문과 같은 크기)
 * @return              AES256_OK(0): 성공, 기타: 실패
 */
int aes256_cbc_decrypt(const uint8_t* p_key,
                       const uint8_t* p_iv,
                       const uint8_t* p_ciphertext,
                       size_t         len,
                       uint8_t*       p_plaintext);
```

### 5.2. 사용 예시

```c
#include "aes256cbc.h"

uint8_t key[32] = { ... };        /* AES-256 키 */
uint8_t iv[16] = { ... };         /* 초기화 벡터 */
uint8_t ciphertext[1024] = { ... };
uint8_t plaintext[1024];

int result = aes256_cbc_decrypt(key, iv, ciphertext, 1024, plaintext);

if (result == AES256_OK) {
    /* 복호화 성공 */
} else {
    /* 복호화 실패 */
}
```

### 5.3. 기술 사양

| 항목 | 값 |
|------|------|
| 알고리즘 | AES-256 |
| 모드 | CBC (Cipher Block Chaining) |
| 키 크기 | 256 bits (32 bytes) |
| 블록 크기 | 128 bits (16 bytes) |
| IV 크기 | 128 bits (16 bytes) |
| 라운드 수 | 14 |
| 패딩 | 없음 (입력은 16바이트 배수) |

### 5.4. 보안 특성

- **Constant-time 구현**: 테이블 룩업 기반으로 타이밍 공격에 대한 기본적인 저항성
- **메모리 클리어**: 함수 종료 시 round_keys 등 민감한 데이터를 스택에서 제거
- **In-place 복호화**: p_plaintext와 p_ciphertext가 같은 버퍼를 사용 가능

## 6. T32 디버깅

`.lib`를 `-g` 옵션으로 빌드하면 디버그 정보가 `.o` -> `.lib` -> `.axf` 순서로 전달됩니다.
`.axf`에 포함된 소스 경로가 현재 PC와 다를 경우, 다음 방법으로 소스 파일을 연결할 수 있습니다.

### 6.1. 검색 경로 추가 (원본 경로를 모를 때)

아래 명령어로 검색 경로를 추가하면 T32가 파일명 기준으로 등록된 디렉토리에서 자동 검색합니다.

```
SYMBOL.SourcePATH.SetDir "[프로젝트 경로]\Src\rsa3072"
SYMBOL.SourcePATH.SetDir + "[프로젝트 경로]\Src\aes256cbc"
```

### 6.2. 경로 변환 (원본 경로를 알 때)

원본 빌드 경로는 `fromelf --text -e output.axf` 또는 T32의 `sYmbol.SourcePath.List`로 확인합니다.
확인된 원본 빌드 경로를 아래 명령어로 변환합니다.

```
SYStem.SourcePath.Translate "[원본 프로젝트 경로]\81_C-Encryption\Src" "[현재 프로젝트 경로]\Src"
```

## 7. 문제 해결

### 7.1. 빌드 에러: "openssl/evp.h not found"

OpenSSL 헤더 경로가 설정되지 않았습니다. Makefile의 `OPENSSL_DIR`을 수정하세요.

### 7.2. RSA 서명 검증 실패

- 공개키 N이 서명 생성에 사용된 키와 일치하는지 확인
- 메시지가 정확히 일치하는지 확인 (trailing newline 주의)
- 서명 데이터가 384 bytes인지 확인

### 7.3. AES 복호화 실패

- 키와 IV가 암호화 시 사용된 것과 동일한지 확인
- 입력 데이터가 16바이트 배수인지 확인
- Big-endian/Little-endian 바이트 순서 확인

## 8. 보안 참고사항

### 8.1. RSA 관련

test/ 폴더의 개인키는 **테스트 목적 전용**입니다.

프로덕션 사용 시:
1. 안전한 환경에서 키 생성
2. 개인키는 안전하게 보관 (HSM 권장)
3. 검증 대상에는 공개키 Modulus N만 배포

### 8.2. AES 관련

- 키와 IV는 안전하게 생성 및 보관
- IV는 암호화마다 고유해야 함 (재사용 금지)
- 키 배포 시 안전한 채널 사용
