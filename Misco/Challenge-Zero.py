str = '36 3B 69 35 78 4A 7D 6A 55 77 35 4C 77 39 72'
a = str.split(' ')
flag = ''
print(a)
for i in a:
    flag += chr(int(i,16)-5)
    print(flag)