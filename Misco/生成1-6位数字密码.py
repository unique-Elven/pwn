arr=000000
for i in range(10000000):
    arr += 1
    with open('123456.txt','wb') as f:
        f.write(arr.str())