import hashlib


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


if __name__ == '__main__':
    Kot = "Kot(1001011 1101111 1110100)"
    Kou = "Kou(1001011 1101111 1110101)"

    md5_kot = hashlib.md5(Kot.encode()).hexdigest()
    md5_kou = hashlib.md5(Kou.encode()).hexdigest()

    sha1_kot = hashlib.sha1(Kot.encode()).hexdigest()
    sha1_kou = hashlib.sha1(Kou.encode()).hexdigest()

    sha256_kot = hashlib.sha256(Kot.encode()).hexdigest()
    sha256_kou = hashlib.md5(Kou.encode()).hexdigest()

    print("kot =", Kot)
    print("kou =", Kou)

    print("md5_kot =", md5_kot)
    print("md5_kou =", md5_kou)
    print("Uniqueness of md5 =", unique_percentage(md5_kot, md5_kou), "%")

    print("sha1_kot =", sha1_kot)
    print("sha1_kou =", sha1_kou)
    print("Uniqueness of sha1 =", unique_percentage(sha1_kot, sha1_kou), "%")

    print("sha256_kot =", sha256_kot)
    print("sha256_kou =", sha256_kou)
    print("Uniqueness of sha256 =", unique_percentage(sha256_kot, sha256_kou), "%")
