from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os, glob, sys, re

file_list = []


def encrypt_file(input_file, key, encrypted_filename):
    
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_file, 'rb') as file:
        data = file.read()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(f'{encrypted_filename}.bin', 'wb') as enc_file:
        enc_file.write(iv + encrypted_data)

    with open("key.txt", 'wb') as key_file:
        key_file.write(key)


def decrypt_file(input_file, output_file, key):

    with open(input_file, 'rb') as file:
        iv = file.read(16)
        encrypted_data = file.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    with open(output_file, 'wb') as file:
        file.write(unpadded_data)

def show_example_key(key_size):
    if key_size == 128:
        example_key = os.urandom(16).hex()
        return example_key
    elif key_size == 192:
        example_key = os.urandom(24).hex()
        return example_key
    elif key_size == 256:
        example_key = os.urandom(32).hex()
        return example_key
    else:
        print(f"Anahtar {key_size} bit olmalıdır.")
    
def generate_key(key_size):
    return os.urandom(key_size // 8)

def is_valid_key(key_str, key_size):
    try:
        key = bytes.fromhex(key_str)
        if len(key) == key_size // 8:
            return key
        else:
            raise ValueError("Anahtar boyutu uyumsuz.")
    except ValueError as e:
        print(f"Geçersiz anahtar girildi.")
        return None

        
def read_key(filename="key.txt"):
    try:
        with open(filename, "rb") as file:
            return file.read()
    except FileNotFoundError:
        print(f"'{filename}' adlı dosya bulunamadı.")
        return None
    except IOError:
        print(f"'{filename}' adlı dosya okunurken hata ile karşılaşıldı.")
        return None


def encoder(key_size, file, encrypted_filename, using_key):

    key = using_key

    input_file = file
    encrypted_file = f'{encrypted_filename}.bin'

    try:
        encrypt_file(input_file, key, encrypted_filename)
        print(f'{input_file} şifrelendi ve {encrypted_file} olarak kaydedildi.')
    except Exception as e:
        print(f"Beklenmedik bir hata ile karşılaşıldı: {e}")

def decoder(encrypted_file, decryption_filename, key):

    decrypted_file = f'{decryption_filename}.pdf'
    
    try:
        decrypt_file(encrypted_file, decrypted_file, key)
        print(f'{encrypted_file} şifresi çözüldü ve {decrypted_file} olarak kaydedildi.')
    except Exception as e:
        print(f"Beklenmedik bir hata ile karşılaşıldı: {e}")


def FileNameControl(file_name):
    if not re.search(r'[\/:*?"<>|,!?;:*]',os.path.splitext(file_name)[1]) and not re.search(r'[\/:*?"<>|.,!?;:*]', os.path.splitext(file_name)[0]):
        return True
    else:
        return False
    
def isNullOrEmpty(value):
    return value is None or (hasattr(value, '__len__') and len(value.strip()) == 0)

import os
import glob

import os
import glob

def list_files(directory, choicefile):
    global file_list
    file_counter = 0
    files = glob.glob(os.path.join(directory, '*'))

    program_file = os.path.basename(__file__)

    file_found = False
    
    for file in files:
        if os.path.isfile(file):
            read_file = os.path.basename(file)

            if read_file == program_file:
                continue

            if choicefile == "E":
                if not file.endswith('.bin'):
                    if not file_found:
                        print("\n[+] Listelenen Dosyalar\n")
                    file_list.append(read_file)
                    print(read_file)
                    file_counter += 1
                    file_found = True
            elif choicefile == "D":
                if file.endswith('.bin'):
                    if not file_found:
                        print("\n[+] Listelenen Dosyalar\n")
                    file_list.append(read_file)
                    print(read_file)
                    file_counter += 1
                    file_found = True

    if file_counter > 0:
        print(f'\n{file_counter} Adet dosya bulundu.\n')

    return file_found


    
def main_func(choice = 0):

    main = """
Dosya Şifreleme Programı                   Proje Bitiş Tarihi: 8 Mart 2025

0- Menü
1- Dosya şifreleme işlemi
2- Dosya deşifreleme işlemi
3- Program hakkında
4- Çıkış   """

    while True:
        select_choice = input("\nİşlem yapılacak dosyaların bulunduğu dizini girin: ")
        if os.path.isdir(select_choice):
            break
        else:
            print("Lütfen istenilen girişi yapınız.")

    os.system('cls')
    print(main)
    
    while True:
        choice = input("\nYapacağınız işlemi seçiniz (0-4): ")
        try:
            choice = int(choice)
        except ValueError:
            print("Geçersiz işlem yapıldı.")
            continue

        if choice == 0:
            os.system('cls')
            print(main)     
        elif choice == 1:
            result = list_files(select_choice, "E")
            if result == False:
                print("Şifrelenecek dosya bulunamadı.")
                return
            while True:
                file_choice = input("Şifrelenecek dosyayı seçin: ")
                if FileNameControl(file_choice): 
                    if file_choice in file_list:
                        print(f'\n{file_choice} adlı dosya seçildi.\n')

                        while True:
                            choice_encrypted_filename = input("Şifrelenecek dosyanın adını giriniz: ")
                            if FileNameControl(choice_encrypted_filename):
                                if os.path.splitext(choice_encrypted_filename)[1]:
                                    print("Dosya uzantısı eklenemez, tekrar giriş yapın.\n")
                                else:
                                    encrypted_filename = choice_encrypted_filename
                                    print(f'\n{encrypted_filename} dosya adı seçildi.\n')
                                    break
                            elif isNullOrEmpty(choice_encrypted_filename):
                                print("İşlem yapabilmek için giriş yapmanız gerekmektedir.\n")
                            else:
                                print("Geçersiz dosya adı girildi.\n")
                        
                        print("Seçilebilecek Anahtar Boyutları")
                        print("1. 128 bit")
                        print("2. 192 bit")
                        print("3. 256 bit")
                        key_choice = input("Anahtar boyutunu seçin (1/2/3/v): ")

                        while True:
                            if isNullOrEmpty(key_choice) or key_choice.lower() not in ['1', '2', '3', 'v']:
                                key_choice = input("\nİşleme devam edebilmek için, istenilen seçeneklerden birini seçiniz.\nAnahtar boyutunu seçin (1/2/3/v): \n")
                            else:
                                if key_choice == "1":
                                    key_size = 128
                                elif key_choice == "2":
                                    key_size = 192
                                elif key_choice == "3":
                                    key_size = 256
                                elif key_choice == "v":
                                    key_size = 128

                                choice_using_key = input(f'\n1- Anahtar Girin \n2- Anahtar Oluştur\n\nKullanılacak {key_size} bit anahtarı girin veya oluşturun (1-2): ')
                                if choice_using_key == "1":
                                    enter_key = input("Anahtar Giriniz: ")
                                    if is_valid_key(enter_key, key_size):
                                        using_key = enter_key
                                        print("\nAnahtar kabul edildi.\n")
                                        break
                                    else:
                                        print(f'\nGeçersiz anahtar girildi. Anahtar {key_size} bit olmalıdır, tekrar deneyin.')
                                elif choice_using_key == "2":
                                    using_key = generate_key(key_size)
                                    print(f'{key_size} Bit anahtar oluşturuldu.')
                                    break
                                else:
                                    print("Lütfen istenilen seçeneklerden birini seçiniz.")
                                
                        encoder(key_size, file_choice, encrypted_filename, using_key)
                        break
                    else:
                        print("Girdiğiniz dosya bulunamadı.\n")
                elif isNullOrEmpty(file_choice):
                    print("İşlem yapabilmek için giriş yapmanız gerekmektedir.\n")
                else:
                    print("Anlamsız giriş yapıldı.\n")
        elif choice == 2:
            result = list_files(select_choice, "D")
            if result == False:
                print("Deşifrelenecek dosya bulunamadı.")
                return
            file_choice = input("Deşifrelenecek dosyayı seçin: ")
            if FileNameControl(file_choice):
                if file_choice in file_list:
                    print(f'\n{file_choice} adlı dosya seçildi.\n')

                    while True:
                        choice_decryption_filename = input("Deşifrelenecek dosyanın adını giriniz: ")
                        if FileNameControl(choice_decryption_filename):
                            if os.path.splitext(choice_decryption_filename)[1]:
                                print("Dosya uzantısı eklenemez, tekrar giriş yapın.\n")
                            else:
                                decryption_filename = choice_decryption_filename
                                print(f'\n{decryption_filename} dosya adı seçildi.\n')
                                break
                        elif isNullOrEmpty(choice_encrypted_filename):
                            print("İşlem yapabilmek için giriş yapmanız gerekmektedir.\n")
                        else:
                            print("Geçersiz dosya adı girildi.\n")
                            
                    decoder(file_choice, decryption_filename, read_key())
                
        elif choice == 3:
            print()
        elif choice == 4:
            print("Programdan çıkıldı.")
            break
        else:
            print("Yanlış seçim yapıldı.")

# Ana program
if __name__ == "__main__":
    main_func()

