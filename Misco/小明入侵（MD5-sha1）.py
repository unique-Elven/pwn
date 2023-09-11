# 题目: 小明入侵网站后获得了管理员的密文,由于太高兴了手一抖把密文删除了一部分,只剩下前10位a74be8e20b,小明根据社工知道管理员的密码习惯是key{4位的数字或字母},所以管理员的密码是.

# 知识点: md5解密

# 解题记录: 查找可知一般的网站管理员的登录密文是经过md5和sha1加密,因为只有四位,故可以使用脚本进行解题.注意构造的字典需要包含大小写字母和数字.
import hashlib
dict = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z']
def cal(a):
    t = hashlib.md5()
    t.update(str(a).encode('ascii'))
    encodestr = t.hexdigest()
    return encodestr

if __name__ == '__main__':
    a=''
    for i in dict:
        for j in dict:
            for n in dict:
                for m in dict:
                    a = 'key{'+str(i)+str(j)+str(n)+str(m)+'}'
                    result = cal(str(a))
                    if result[0:10] == 'a74be8e20b':
                        print(a)
                        print(result)
                    else:
                        pass
                        # print(a) #不要输出速度会更快
                        # print(result)