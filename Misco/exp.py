import os
path = r'c5'
dir1 = os.listdir(path)
f = open('flag','w+')
for x in range(1,101):
    file = open(path+os.sep+str(x),'rb')
    text = str(file.readlines())
    top_size = text.find('flag')
    text = text[top_size:top_size+29]
    f.write(str(x)+' '+text+'\n')
    file.close()
f.close()