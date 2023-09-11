for i in range(10000,99999):
    key = "nsfocus" + str(i) + '\n'
    with open('啧啧啧.txt','a+') as f:
        f.write(key)
    if (i == 99999):
        break