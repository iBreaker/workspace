#!/usr/bin/python
# -*-coding:utf-8-*-
import urllib2
import time
import re
normal_word = re.compile(r'[\w+|\.]')
hex_word = re.compile(r'[0-7]{1}[a-f|A-F|\d]{1}')

'''
分析时， /  " num :的组合 大于等于2个  这元组作废
2015.10.28 添加@到切分词组
'''
punctuation = '''
                ! @ # " $ \' & ) ( + * - , / ; : = < ? > [ ] \\ ^ ` { } | ~
                \a \t \r \v \b \n
                \x00 \x01 \x02 \x03 \x04 \x05 \x06 \x07 \x08 \x09 \x0a \x0b \x0c \x0d \x0e \x0f
                \x10 \x11 \x12 \x13 \x14 \x15 \x16 \x17 \x18 \x19 \x1a \x1b \x1c \x1d \x1e \x1f
                \x80 \x81 \x82 \x83 \x84 \x85 \x86 \x87 \x88 \x89 \x8a \x8b \x8c \x8d \x8e \x8f
                \x90 \x91 \x92 \x93 \x94 \x95 \x96 \x97 \x98 \x99 \x9a \x9b \x9c \x9d \x9e \x9f
                \xa0 \xa1 \xa2 \xa3 \xa4 \xa5 \xa6 \xa7 \xa8 \xa9 \xaa \xab \xac \xad \xae \xaf
                \xb0 \xb1 \xb2 \xb3 \xb4 \xb5 \xb6 \xb7 \xb8 \xb9 \xba \xbb \xbc \xbd \xbe \xbf
                \xc0 \xc1 \xc2 \xc3 \xc4 \xc5 \xc6 \xc7 \xc8 \xc9 \xca \xcb \xcc \xcd \xce \xcf
                \xd0 \xd1 \xd2 \xd3 \xd4 \xd5 \xd6 \xd7 \xd8 \xd9 \xda \xdb \xdc \xdd \xde \xdf
                \xe0 \xe1 \xe2 \xe3 \xe4 \xe5 \xe6 \xe7 \xe8 \xe9 \xea \xeb \xec \xed \xee \xef
                \xf0 \xf1 \xf2 \xf3 \xf4 \xf5 \xf6 \xf7 \xf8 \xf9 \xfa \xfb \xfc \xfd \xfe \xff
        '''
punctuation_set = set()
_ = [punctuation_set.add(i) for i in punctuation]

'''
2015.11.5 在不保留字符集增加 \xa0 \x09 \x0a \x0b \x0c \x0d
1%27%a0union%a0select%a0flag%a0from%a0flag.flag%a0limit%a00,1--%20--
'''
none_save_punctuation = ') } [ ] , - \x00 \x07 \x05 \x01 \a \t \r \v \b \n \xa0 \x09 \x0a \x0b \x0c \x0d'
none_save_punctuation_set = set()
_ = [none_save_punctuation_set.add(i) for i in none_save_punctuation]

'''
2015.11.5
2 union select你 1
对以上字符集避免误报，因此不删除 中文字符集
'''
hexadecimal_ascii_punctuation  = '''
                \x00 \x01 \x02 \x03 \x04 \x05 \x06 \x07 \x08 \x09 \x0a \x0b \x0c \x0d \x0e \x0f
                \x10 \x11 \x12 \x13 \x14 \x15 \x16 \x17 \x18 \x19 \x1a \x1b \x1c \x1d \x1e \x1f
                \x80 \x81 \x82 \x83 \x84 \x85 \x86 \x87 \x88 \x89 \x8a \x8b \x8c \x8d \x8e \x8f
                \x90 \x91 \x92 \x93 \x94 \x95 \x96 \x97 \x98 \x99 \x9a \x9b \x9c \x9d \x9e \x9f
                \xa0 \xa1 \xa2 \xa3 \xa4 \xa5 \xa6 \xa7 \xa8 \xa9 \xaa \xab \xac \xad \xae \xaf
                \xb0 \xb1 \xb2 \xb3 \xb4 \xb5 \xb6 \xb7 \xb8 \xb9 \xba \xbb \xbc \xbd \xbe \xbf
                \xc0 \xc1 \xc2 \xc3 \xc4 \xc5 \xc6 \xc7 \xc8 \xc9 \xca \xcb \xcc \xcd \xce \xcf
                \xd0 \xd1 \xd2 \xd3 \xd4 \xd5 \xd6 \xd7 \xd8 \xd9 \xda \xdb \xdc \xdd \xde \xdf
                \xe0 \xe1 \xe2 \xe3 \xe4 \xe5 \xe6 \xe7 \xe8 \xe9 \xea \xeb \xec \xed \xee \xef
                \xf0 \xf1 \xf2 \xf3 \xf4 \xf5 \xf6 \xf7 \xf8 \xf9 \xfa \xfb \xfc \xfd \xfe \xff
                    '''
hexadecimal_ascii_punctuation_set = set()
_ = [hexadecimal_ascii_punctuation_set.add(i) for i in hexadecimal_ascii_punctuation]


def check_is_file(strings):
    str_list = strings.split('.')
    if len(str_list) != 2:
        return False
    else:
        if str_list[1] in ['txt', 'php', 'html', 'asp', 'log', 'so']:
            return True
        else:
            return False


def check_is_ip(strings):
    num_list = strings.split('.')
    if len(num_list) != 4:
        return False
    else:
        count = 0
        for i in num_list:
            try:
                float(i)
                count += 1
            except Exception as e:
                return False
        return True


def check_is_num(strings):
    if strings.isdigit():
        return True
    else:
        return False
    # try:
    #     float(strings)
    #     return True
    # except Exception as e:
    #     return False


def change_word(word):
    if check_is_num(word):
        word = 'NUM'
    elif word.startswith("0") and word.startswith("0x"):
        word = 'Character_encoding_0x'
    elif word.endswith('n') and word.endswith('union'):
        '''
        2015.11.5
        解决xxoo 100.union select flag from flag.flag 问题
        '''
        word = 'union'
    # if check_is_ip(word):
    #     word = 'format_is_ipaddress'
    # if check_is_file(word):
    #     word = 'format_is_file'
    return word


# @profile
def segmentation_common2word(strings, status='analysis'):
    start_time = time.time()
    '''
    不保留字符为
              ) } [ ] , - \x00 \x07 \x05 \x01 \a \t \r \v \b \n
    '''
    strings = strings.lower()
    strings = strings.replace('\'', '"')
    if len(strings) == 0:
        return [], 3
    # strings_list = ['star_self_blank','star_self_blank']
    strings_list = []
    word = ''
    for i in strings:
        if i in punctuation_set:
            if len(word) > 0:
                word = change_word(word)
                strings_list.append(word)
            if i != ' ' and i not in none_save_punctuation:
                strings_list.append(i)
            word = ''
        else:
            word += i
    if len(word) > 0:
        word = change_word(word)
        strings_list.append(word)
    if len(strings_list) == 2:
        strings_list.insert(0, 'star_self_blank')
    elif len(strings_list) == 1:
        strings_list.insert(0, 'star_self_blank')
        strings_list.insert(0, 'star_self_blank')
    # print time.time() - start_time
    if status == 'analysis':
        return tuple(strings_list), 3
    else:
        word_list = []
        for i in strings_list:
            if i in hexadecimal_ascii_punctuation_set:
                word_list.append('Hexadecimal_ASCII')
            else:
                word_list.append(i)
        new_word_list = []
        i = 0
        j = 0
        double_flag = -1
        first_double = -1
        hex_flag = -1
        # print word_list
        while i < len(word_list):
            if word_list[i] == '"':
                if first_double < 0:
                    double_flag = 0
                    first_double = 0

                if double_flag < 0:
                    double_flag = i
                elif first_double == 0:
                    if i - double_flag == 1:
                        double_flag = -1
                        first_double = 1
                    else:
                        double_flag = i
                        first_double = 1
                else:
                    if i - double_flag == 2 and normal_word.match(word_list[i - 1]):
                        new_word_list.pop()
                        new_word_list[j - 2] = 'STR'
                        double_flag = -1
                        j -= 1
                        i += 1
                        continue
                    else:
                        double_flag = i
            elif i - double_flag > 2:
                double_flag = -1
            # if judge_num(word_list[i]):
            #     word_list[i] = 'NUM'
            if word_list[i] == '#' and i - 1 >= 0 and word_list[i - 1] == '&':
                hex_flag = i
            if hex_flag >= 0 and hex_flag == i - 1:
                # 十进制html编码
                if word_list[i] == 'NUM' and i + 1 < len(word_list) and word_list[i + 1] == ';':
                    new_word_list.pop()
                    new_word_list[j - 2] = 'HEX_HTML'
                    hex_flag = -1
                    j -= 1
                    i += 2
                    continue
                # 十六进制html编码
                elif word_list[i][0] == 'x' and i + 1 < len(word_list) and word_list[i + 1] == ';':
                    if hex_word.match(word_list[i][1:]):
                        new_word_list.pop()
                        new_word_list[j - 2] = 'HEX_HTML'
                        hex_flag = -1
                        j -= 1
                        i += 2
                        continue
                else:
                    hex_flag = -1
            new_word_list.append(word_list[i])
            j += 1
            i += 1

        if 'NUM > <' in ' '.join(new_word_list):
            print strings
        return new_word_list, 3


# @profile
def segmentation_common2word_bak(strings):
    start_time = time.time()
    '''
    保留字符为
              ( = / * " ; < : > % | & { +
    '''
    strings = strings.lower()
    strings = strings.replace('\'', '"')
    if len(strings) == 0:
        return [], 3
    # strings_list = ['star_self_blank','star_self_blank']
    strings_list = []
    word = ''
    c = None
    for i in strings:
        if i in punctuation_set:
            if len(word) > 0:
                word = change_word(word)
                strings_list.append(word)
            if i != ' ' and i in save_punctuation_set:
                strings_list.append(i)
            c = i
            word = ''
        else:

            word += i
    if word != '':
        if len(word) > 0:
            word = change_word(word)
            strings_list.append(word)
    if len(strings_list) == 2:
        strings_list.insert(0, 'star_self_blank')
    elif len(strings_list) == 1:
        strings_list.insert(0, 'star_self_blank')
        strings_list.insert(0, 'star_self_blank')
    # print time.time() - start_time
    return tuple(strings_list), 3


def adjust_common2_valuation():
    '''
    返回值为两项，第一项为调整的列表，第二项为是否使用古德图灵参数
    '''
    return [], True

def segmentation_common2word_split(strings, status='analysis', split = ' '):
    t,_ = segmentation_common2word(strings,status)
    return split.join(t)

if __name__ == '__main__':
    # payload = '''
    # _TEL:<170+7038+7170><123123
    # '''
    payload = '''
    /pandora_console/index.php?loginhash_data=21232f297a57a5a743894a0e4a801fc3&loginhash_user=admin&loginhash=1 HTTP/1.1
    '''
    import time
    import urllib2
    payload = urllib2.unquote(payload)

    start_time = time.time()
    print segmentation_common2word(payload, status='building')
    print time.time() - start_time

    start_time = time.time()
    print segmentation_common2word(payload, status='analysis')
    print time.time() - start_time

    start_time = time.time()
    print segmentation_common2word_split(payload)
    print time.time() - start_time