
import html
def string_reverse(string):
    return string[::-1]
string = ';201#&;801#&;79#&;301#&;321#&;75#&;89#&;101#&;45#&;94#&;001#&;201#&;15#&;94#&;94#&;79#&;55#&;35#&;35#&;45#&;99#&;84#&;001#&;84#&;25#&;75#&;05#&;45#&;55#&;001#&;55#&;99#&;45#&;99#&;15#&;94#&;15#&;521#&'
fan_string = string_reverse(string)
print(fan_string + '\n')
txt = html.unescape(fan_string)
print(txt + '\n')
print(string_reverse(txt) + '\n')