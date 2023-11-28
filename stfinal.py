import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import numpy as np

def caesar_cipher(text, key):
    result = ""
    for char in text:
        if char.isalpha():
            shift = 65 if char.isupper() else 97
            result += chr((ord(char) + key - shift) % 26 + shift)
        else:
            result += char
    return result

def encrypt_cover_text(file_name, key):
    with open(file_name, "r") as file:
        plaintext = file.read()

    encrypted_text = caesar_cipher(plaintext, key)

    with open("covertext_encrypted.txt", "w") as file:
        file.write(encrypted_text)

    txt_encode("VendorSphere" + str(key), "covertext_encrypted.txt")

def caesar_decipher(text, key):
    return caesar_cipher(text, -key)

def remove_unicode(file_path, output_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        text = file.read()

    cleaned_text = ''.join(char for char in text if ord(char) < 128)

    with open(output_path, 'w', encoding='utf-8') as output_file:
        output_file.write(cleaned_text)

def decrypt_cover_text(inputFile, key):
    input_file_path = inputFile
    output_file_path = inputFile
    remove_unicode(input_file_path, output_file_path)
    with open(output_file_path, "r") as file:
        encrypted_text = file.read()

    decrypted_text = caesar_decipher(encrypted_text, key)

    with open("covertext_decrypted.txt", "w") as file:
        file.write(decrypted_text)

def txt_encode(text, filee):
    l = len(text)
    i = 0
    add = ''
    while i < l:
        t = ord(text[i])
        if(t >= 32 and t <= 64):
            t1 = t + 48
            t2 = t1 ^ 170
            res = bin(t2)[2:].zfill(8)
            add += "0011" + res
        else:
            t1 = t - 48
            t2 = t1 ^ 170
            res = bin(t2)[2:].zfill(8)
            add += "0110" + res
        i += 1
    res1 = add + "111111111111"
    print("The string after binary conversion applying all the transformation: " + (res1))
    length = len(res1)
    print("Length of binary after conversion: ", length)
    HM_SK = ""
    ZWC = {"00": u'\u200C', "01": u'\u202C', "11": u'\u202D', "10": u'\u200E'}
    file1 = open(filee, "r+")
    nameoffile = input("\nEnter the name of the Stego file after Encoding (with extension): ")
    file3 = open(nameoffile, "w+", encoding="utf-8")
    word = []
    for line in file1:
        word += line.split()
    i = 0
    while(i < len(res1)):
        s = word[int(i/12)]
        j = 0
        x = ""
        HM_SK = ""
        while(j < 12):
            x = res1[j+i] + res1[i+j+1]
            HM_SK += ZWC[x]
            j += 2
        s1 = s + HM_SK
        file3.write(s1)
        file3.write(" ")
        i += 12
    t = int(len(res1)/12)
    while t < len(word):
        file3.write(word[t])
        file3.write(" ")
        t += 1
    file3.close()
    file1.close()
    print("\nStego file has been successfully generated")

def BinaryToDecimal(binary):
    string = int(binary, 2)
    return string

def decode_txt_data():
    ZWC_reverse = {u'\u200C': "00", u'\u202C': "01", u'\u202D': "11", u'\u200E': "10"}
    stego = input("\nPlease enter the stego file name (with extension) to decode the message: ")

    with open(stego, "r", encoding="utf-8") as file4:
        lines = file4.readlines()

    temp = ''
    is_hidden_message = False

    for line in lines:
        for words in line.split():
            T1 = words
            binary_extract = ""
            for letter in T1:
                if letter in ZWC_reverse:
                    binary_extract += ZWC_reverse[letter]
            if binary_extract == "111111111111":
                is_hidden_message = True
                break
            else:
                temp += binary_extract

    print("\nEncrypted message presented in code bits:", temp)
    lengthd = len(temp)
    print("\nLength of encoded bits: ", lengthd)

    i = 0
    a = 0
    b = 4
    c = 4
    d = 12
    final = ''
    while i < len(temp):
        t3 = temp[a:b]
        a += 12
        b += 12
        i += 12
        t4 = temp[c:d]
        c += 12
        d += 12
        if t3 == '0110':
            decimal_data = BinaryToDecimal(t4)
            final += chr((decimal_data ^ 170) + 48)
        elif t3 == '0011':
            decimal_data = BinaryToDecimal(t4)
            final += chr((decimal_data ^ 170) - 48)

    print("\nMessage after decoding from the stego file:", final)

    marker_start = "#START_ENCODED_MESSAGE#"
    marker_end = "#END_ENCODED_MESSAGE#"

    with open(stego, "w", encoding="utf-8") as file4:
        for line in lines:
            if not is_hidden_message or (marker_start not in line and marker_end not in line):
                file4.write(line)

def msgtobinary(msg):
    if type(msg) == str:
        result = ''.join([format(ord(i), "08b") for i in msg])
    elif type(msg) == bytes or type(msg) == np.ndarray:
        result = [format(i, "08b") for i in msg]
    elif type(msg) == int or type(msg) == np.uint8:
        result = format(msg, "08b")
    else:
        raise TypeError("Input type is not supported in this function")
    return result

def KSA(key):
    key_length = len(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def PRGA(S, n):
    i = 0
    j = 0
    key = []
    while n > 0:
        n = n-1
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        key.append(K)
    return key

def preparing_key_array(s):
    return [ord(c) for c in s]

def encryption(plaintext):
    print("Enter the key : ")
    key = input()
    key = preparing_key_array(key)

    S = KSA(key)

    keystream = np.array(PRGA(S, len(plaintext)))
    plaintext = np.array([ord(i) for i in plaintext])

    cipher = keystream ^ plaintext
    ctext = ''
    for c in cipher:
        ctext = ctext + chr(c)
    return ctext

def decryption(ciphertext):
    print("Enter the key : ")
    key = input()
    key = preparing_key_array(key)

    S = KSA(key)

    keystream = np.array(PRGA(S, len(ciphertext)))
    ciphertext = np.array([ord(i) for i in ciphertext])

    decoded = keystream ^ ciphertext
    dtext = ''
    for c in decoded:
        dtext = dtext + chr(c)
    return dtext

def main():
    def update_labels():
        encrypted_label.config(text="Encrypted and encoded: " + encrypted_file.get())
        decrypted_label.config(text="Decrypted: " + decrypted_file.get())

    def encrypt_file():
        file_path = filedialog.askopenfilename(title="Select File to Encrypt")
        key = int(entry_key.get())
        try:
            encrypt_cover_text(file_path, key)
            encrypted_file.set("covertext_encrypted.txt")
            update_labels()
            messagebox.showinfo("Success", "Encryption and encoding completed successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def decrypt_file():
        file_path = filedialog.askopenfilename(title="Select File to Decrypt")
        key = int(entry_key.get())
        try:
            decrypt_cover_text(file_path, key)
            decrypted_file.set("covertext_decrypted.txt")
            update_labels()
            messagebox.showinfo("Success", "Decryption and decoding completed successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def decode_stego():
        try:
            decode_txt_data()
            decoded_file.set("Decoded message: See console for output")
            update_labels()
            messagebox.showinfo("Success", "Decoding stego file completed successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    root = tk.Tk()
    root.title("Steganography Tool")

    frame = ttk.Frame(root, padding="10")
    frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

    label_key = ttk.Label(frame, text="Enter the key:")
    label_key.grid(row=0, column=0, pady=5, padx=5)

    entry_key = ttk.Entry(frame)
    entry_key.grid(row=0, column=1, pady=5, padx=5)

    button_encrypt = ttk.Button(frame, text="Encrypt and Encode File", command=encrypt_file)
    button_encrypt.grid(row=1, column=0, columnspan=2, pady=10)

    button_decrypt = ttk.Button(frame, text="Decrypt File", command=decrypt_file)
    button_decrypt.grid(row=2, column=0, columnspan=2, pady=10)

    button_decode_stego = ttk.Button(frame, text="Decode Stego File", command=decode_stego)
    button_decode_stego.grid(row=3, column=0, columnspan=2, pady=10)

    button_exit = ttk.Button(frame, text="Exit", command=root.destroy)
    button_exit.grid(row=4, column=0, columnspan=2, pady=10)

    encrypted_file = tk.StringVar()
    decrypted_file = tk.StringVar()

    encrypted_label = ttk.Label(frame, text="Encrypted and encoded: ")
    encrypted_label.grid(row=5, column=0, columnspan=2, pady=5)
    decrypted_label = ttk.Label(frame, text="Decrypted: ")
    decrypted_label.grid(row=6, column=0, columnspan=2, pady=5)

    root.mainloop()

if __name__ == "__main__":
    main()
