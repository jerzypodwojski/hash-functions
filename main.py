import hashlib
import time


def unique_percentage(string1, string2):
    counter = 0
    if len(string1) < len(string2):
        min_length = len(string1)
    else:
        min_length = len(string2)

    for i in range(min_length):
        if string1[i] == string2[i]:
            counter += 1

    return 100 - (counter / min_length) * 100


def check_uniqueness():
    Kot = b"100101111011111110100"
    Kou = b"100101111011111110101"

    md5_kot = hashlib.md5(Kot).hexdigest()
    md5_kou = hashlib.md5(Kou).hexdigest()
    md5_kot = (bin(int(md5_kot, 16))[2:])
    md5_kou = (bin(int(md5_kou, 16))[2:])

    sha1_kot = hashlib.sha1(Kot).hexdigest()
    sha1_kou = hashlib.sha1(Kou).hexdigest()
    sha1_kot = (bin(int(sha1_kot, 16))[2:])
    sha1_kou = (bin(int(sha1_kou, 16))[2:])

    sha224_kot = hashlib.sha224(Kot).hexdigest()
    sha224_kou = hashlib.sha224(Kou).hexdigest()
    sha224_kot = (bin(int(sha224_kot, 16))[2:])
    sha224_kou = (bin(int(sha224_kou, 16))[2:])

    sha256_kot = hashlib.sha256(Kot).hexdigest()
    sha256_kou = hashlib.sha256(Kou).hexdigest()
    sha256_kot = (bin(int(sha256_kot, 16))[2:])
    sha256_kou = (bin(int(sha256_kou, 16))[2:])

    sha384_kot = hashlib.sha384(Kot).hexdigest()
    sha384_kou = hashlib.sha384(Kou).hexdigest()
    sha384_kot = (bin(int(sha384_kot, 16))[2:])
    sha384_kou = (bin(int(sha384_kou, 16))[2:])

    print("kot =", Kot)
    print("kou =", Kou)

    print("md5_kot =", md5_kot)
    print("md5_kou =", md5_kou)
    print("Uniqueness of md5 =", unique_percentage(md5_kot, md5_kou), "%")

    print("sha1_kot =", sha1_kot)
    print("sha1_kou =", sha1_kou)
    print("Uniqueness of sha1 =", unique_percentage(sha1_kot, sha1_kou), "%")

    print("sha224_kot =", sha224_kot)
    print("sha224_kou =", sha224_kou)
    print("Uniqueness of sha224 =", unique_percentage(sha224_kot, sha224_kou), "%")

    print("sha256_kot =", sha256_kot)
    print("sha256_kou =", sha256_kou)
    print("Uniqueness of sha256 =", unique_percentage(sha256_kot, sha256_kou), "%")

    print("sha384_kot =", sha384_kot)
    print("sha384_kou =", sha384_kou)
    print("Uniqueness of sha384 =", unique_percentage(sha384_kot, sha384_kou), "%")


def custom_message(message):
    print("MD5:", hashlib.md5(message.encode()).hexdigest())
    print("SHA1:", hashlib.sha1(message.encode()).hexdigest())
    print("SHA224:", hashlib.sha224(message.encode()).hexdigest())
    print("SHA256:", hashlib.sha256(message.encode()).hexdigest())
    print("SHA384:", hashlib.sha384(message.encode()).hexdigest())


def check_file(chosen_file):
    results_num = 10
    open('results.txt', 'w').close()
    open('results.txt', 'a')

    if chosen_file == "1":
        with open('500.txt', 'rb') as file:
            data = file.read()
        print("Chosen file: 500KB")

    if chosen_file == "2":
        with open('2.txt', 'rb') as file:
            data = file.read()
        print("Chosen file: 2MB")

    if chosen_file == "3":
        with open('5.txt', 'rb') as file:
            data = file.read()
        print("Chosen file: 5MB")

    with open("results.txt", "a") as file:
        file.write("md5\n")
    for i in range(results_num):
        start = time.time()
        data_md5 = hashlib.md5(data).hexdigest()
        end = time.time()
        md5_time = (end - start)
        with open("results.txt", "a") as file:
            file.write(str(md5_time) + '\n')

    with open("results.txt", "a") as file:
        file.write("sha1\n")
    for i in range(results_num):
        start = time.time()
        data_sha1 = hashlib.sha1(data).hexdigest()
        end = time.time()
        sha1_time = (end - start)
        with open("results.txt", "a") as file:
            file.write(str(sha1_time) + '\n')

    with open("results.txt", "a") as file:
        file.write("sha224\n")
    for i in range(results_num):
        start = time.time()
        data_sha224 = hashlib.sha224(data).hexdigest()
        end = time.time()
        sha224_time = (end - start)
        with open("results.txt", "a") as file:
            file.write(str(sha224_time) + '\n')

    with open("results.txt", "a") as file:
        file.write("sha256\n")
    for i in range(results_num):
        start = time.time()
        data_sha256 = hashlib.sha256(data).hexdigest()
        end = time.time()
        sha256_time = (end - start)
        with open("results.txt", "a") as file:
            file.write(str(sha256_time) + '\n')

    with open("results.txt", "a") as file:
        file.write("sha384\n")
    for i in range(results_num):
        start = time.time()
        data_sha384 = hashlib.sha384(data).hexdigest()
        end = time.time()
        sha384_time = (end - start)
        with open("results.txt", "a") as file:
            file.write(str(sha384_time) + '\n')

    print("MD5 | length:", len(data_md5), "| execution time:", md5_time)
    print("SHA1 | length:", len(data_sha1), "| execution time:", sha1_time)
    print("SHA224 | length:", len(data_sha224), "| execution time:", sha224_time)
    print("SHA256 | length:", len(data_sha256), "| execution time:", sha256_time)
    print("SHA384 | length:", len(data_sha384), "| execution time:", sha384_time)
    print("Check results.txt for more execution time examples.")


if __name__ == '__main__':
    while True:
        menu = input("1. Check uniqueness\n"
                     "2. Custom message\n"
                     "3. Check speed and length of hash functions\n...\n")

        if menu == "1":
            check_uniqueness()

        if menu == "2":
            custom_message(input("Type message: \n"))

        if menu == "3":
            speed_menu = input("Choose file size:\n"
                               " 1 - 500KB\n"
                               " 2 - 2MB\n"
                               " 3 - 5MB\n")
            if speed_menu == "1" or speed_menu == "2" or speed_menu == "3":
                check_file(speed_menu)
