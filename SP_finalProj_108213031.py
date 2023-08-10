import os, sys
LocCounter = None
opcode_table = {}
symbol_table = {}
object_code = {}
outputPass1 = []
lineNum = 1
errorNum = 0

def search_opCode(mnemonic):
    global opcode_table
    if opcode_table.get(mnemonic, 0) == 0:
        # 沒找到
        return False
    else:
        # 有找到
        return True

def build_intermediateTab():
    global errorNum

    intermediate_table=[]
    intermediateFilePath = 'intermediate.txt'
    middleFile = open(intermediateFilePath, 'r')

    for line in middleFile.readlines():
        token = line.split()
        intermediate_table.append(token)
    # 把 0x 去掉
    for i in range(1, len(intermediate_table)-1):
        intermediate_table[i][1] = intermediate_table[i][1][2:]
    intermediate_table[len(intermediate_table)-1][0] = intermediate_table[len(intermediate_table)-1][0][2:]

    return intermediate_table

def insert_symbolTab(symbol, LocCounter):
    global symbol_table
    global errorNum

    if symbol in symbol_table:
        errorNum += 1
        print('Error, duplicate definition, in line:', lineNum)
        return # 如果這個 label 已經被記過了 就不用再記一次
    else:
        symbol_table[symbol] = hex(LocCounter)

def printErec(intermediate_table): # E ^ 指定的 label 位置
    global symbol_table
    global errorNum

    eRecordTab = ['E']
    if symbol_table.get(intermediate_table[len(intermediate_table)-2][4], 0) == 0: # 沒找到
        errorNum += 1
        print('Error, operand undefined, in line:', intermediate_table[len(intermediate_table)-2][0])
        return 0
    else:
        intermediate_table[len(intermediate_table)-2][4] = symbol_table.get(intermediate_table[len(intermediate_table)-2][4])[2:].rjust(6, '0')
        eRecordTab.append(intermediate_table[len(intermediate_table)-2][4])
        return eRecordTab

def build_tRecordTab(tRecord, tRecordTab, capacity):
    tRecordTab_tmp = ['T'] # 用來統整此行 T record，統整完再加進 tRecordTab
    tRecordTab_tmp.append(tRecord[0].get("initAddress").zfill(6)) # 加入初始位置(第一個 object code 的記憶體位置)
    tRecordTab_tmp.append(hex(int(capacity))[2:].zfill(2)) # 長度填 0
    for i in range(len(tRecord)): # 加入所有 obj code
        tRecordTab_tmp.append(tRecord[i].get("objectCode"))
    tRecordTab.append(tRecordTab_tmp)
    return [], tRecordTab, 0

def printTrec(intermediate_table): # T ^ 起始位置 ^ 指令總大小 ^ object code
    global symbol_table
    global errorNum

    nowTrec = 1 # 現在 Trec 做到了哪一行
    capacity = 0 # 檢查該軌 Trec 的長度有沒有超過
    tRecordTab = [] # 統整紀錄要輸出的 T record
    tRecord = [] # 儲存這一行 T record 裡面要放的 object code 及其記憶體位置，結構:[{}, {}, {}...]
    objCode = {}# 現在正在編譯的那行指令，結構: {"這行指令的記憶體位置": 記憶體位置, "objectCode": objectCode}

    for nowTrec in range(1, len(intermediate_table)-2):
        # 先做出 opcode，檢查看看這個指令放進去空間夠不夠，夠的話就放進去，不夠的話就換下一行放
        # 先檢查是不是虛指令
        if intermediate_table[nowTrec][3] == 'RESW' or intermediate_table[nowTrec][3] == 'RESB':
            if len(tRecord) > 0:
                # 把目前累積在 tRecord 的指令清給 tRecordTab(=換行)，長度清零，就繼續下一行指令
                tRecord, tRecordTab, capacity = build_tRecordTab(tRecord, tRecordTab, capacity)
            continue # 這個指令的工作結束了
        
        elif intermediate_table[nowTrec][3] == 'WORD': # WORD 要補六碼 大小: 3
            intermediate_table[nowTrec][4] = intermediate_table[nowTrec][4].rjust(6, '0')
            objCode = {"initAddress": intermediate_table[nowTrec][1], "objectCode" : intermediate_table[nowTrec][4]}
                
        elif intermediate_table[nowTrec][3] == 'BYTE': # BYTE 照填 大小: 字串長度/2
            objCode = {"initAddress": intermediate_table[nowTrec][1], "objectCode" : intermediate_table[nowTrec][4]}
        else:
            # 先去 intermediate_table[5] 獲取 opcode 代碼
            opCode = intermediate_table[nowTrec][5]
            if intermediate_table[nowTrec][4] != '***': # 如果有 operand
                # 判斷定址模式
                if intermediate_table[nowTrec][6] == 'indexed': # 如果是 indexed，記憶體位置第一個數字要 +8 
                    indexedOperand = intermediate_table[nowTrec][4][:intermediate_table[nowTrec][4].find(",")]
                    if symbol_table.get(indexedOperand, 0) == 0:
                        errorNum += 1
                        print('Error, operand undefined, in line:', intermediate_table[nowTrec][0])
                    else:
                        operandAddr = symbol_table.get(indexedOperand)[2:]
                        indexedAddr = hex(8 + int(operandAddr[0]))[2:] + operandAddr[1:]
                        opCode += indexedAddr
                else:
                    if symbol_table.get(intermediate_table[nowTrec][4], 0) == 0:
                        errorNum += 1
                        print('Error, operand undefined, in line:', intermediate_table[nowTrec][0])
                    else:
                        opCode += symbol_table.get(intermediate_table[nowTrec][4])[2:]
                objCode = {"initAddress": intermediate_table[nowTrec][1], "objectCode" : opCode}
            else: # 沒有 operand，補齊六碼
                objCode = {"initAddress": intermediate_table[nowTrec][1], "objectCode" : opCode.ljust(6, '0')}
        
        # 建完這行的 object code，檢查這個指令放進去空間夠不夠
        if len(objCode.get("objectCode"))/2 + capacity > 30: # > 30了，要換行了
            # 裡面有累積的 object code 的話，先清空輸出
            if len(tRecord) > 0:
                tRecord, tRecordTab, capacity = build_tRecordTab(tRecord, tRecordTab, capacity)
            # 清空完，現在要來加入這行 object code
            while len(objCode.get("objectCode")) > 60: # (如果符合條件就一直進去做)如果這行 object code > 30 bytes
                # 要切斷 object code，切長度 60 為一行  objCode.get("objectCode")[:59]
                # 新增一個暫時的 {} 來存被切出去要儲存的 object code 資料結構
                slice_objCode = {"initAddress": objCode.get("initAddress"), "objectCode": objCode.get("objectCode")[:60]}
                # print(objCode.get("objectCode"))
                
                tRecord.append(slice_objCode) # 把這個剛轉完的 object code 放進剛剛被清空的 tRecord
                capacity = 30
                # 加完之後直接清空輸出
                tRecord, tRecordTab, capacity = build_tRecordTab(tRecord, tRecordTab, capacity)
                # print(int("0x" + objCode.get("initAddress"), 16) + 30)
                # print(hex(int("0x" + objCode.get("initAddress"), 16) + 30)[2:])
                # 把 objCode 的 "initAddress" + 30，"objectCode" 更新為剩下的還沒加進去的 code
                objCode["initAddress"] = hex(int("0x" + objCode.get("initAddress"), 16) + 30)[2:]
                objCode["objectCode"] = objCode.get("objectCode")[60:] 

            # (如果還有指令，但長度 <= 60 or 這個指令根本就 < 60，只不過是上一行塞不下罷了) 就把他加進 tRecord，並且更改長度
            tRecord.append(objCode) # 把這個剛轉完的 object code 放進剛剛被清空的 tRecord
            capacity = len(objCode.get("objectCode"))/2 # 長度也更改為此段長度
            
        else: # 空間夠
            tRecord.append(objCode)
            capacity += len(objCode.get("objectCode"))/2
    if len(tRecord) > 0: # 如果已經做到最後一行了，tRecord 中還有之前累積的指令，就一起輸出給 tRecordTab
        tRecord, tRecordTab, capacity = build_tRecordTab(tRecord, tRecordTab, capacity)
    return tRecordTab

def printHrec(intermediate_table): # H ^ 程式名稱 ^ 程式起始位置 ^ 程式總長
    global errorNum

    hRecordTab = ['H']
    # 程式名稱要補空格到 6 碼 (前面已經檢查過程式名稱有沒有過長的問題了，所以一定會在 6 碼以內)
    intermediate_table[0][1] = intermediate_table[0][1].ljust(6) 
    # 起始位置& 程式大小前面要補 0 到六碼
    intermediate_table[0][2] = intermediate_table[0][2].rjust(6, '0')
    intermediate_table[len(intermediate_table)-1][0] = intermediate_table[len(intermediate_table)-1][0].rjust(6, '0')

    hRecordTab.append(intermediate_table[0][1]) # prog name
    hRecordTab.append(intermediate_table[0][2]) # prog 起始位置
    hRecordTab.append(intermediate_table[len(intermediate_table)-1][0]) # prog 總長
    return hRecordTab

def passTwoProg():
    global symbol_table
    global errorNum

    object_program = []
    intermediate_table = build_intermediateTab()
    # intermediate_table=outputPass1
    hRecordTab = printHrec(intermediate_table)
    tRecordTab = printTrec(intermediate_table)
    eRecordTab = printErec(intermediate_table)

    
    if errorNum != 0: # 有錯
        pass
    else:
        object_program.append(hRecordTab)
        for i in range(len(tRecordTab)):
            object_program.append(tRecordTab[i])
        object_program.append(eRecordTab)
        for i in range(len(object_program)):
            print(*object_program[i])

    objectProgramFilePath = 'objectProgram.txt'
    objectProgramFile = open(objectProgramFilePath, 'w')
    for i in range(len(object_program)):
        for j in range(len(object_program[i])):
            objectProgramFile.write(str(object_program[i][j])+' ')
        objectProgramFile.write('\n')
    objectProgramFile.close()


# 要加入如果程式名稱>6就錯 看看 START 後面有沒有加入起始位置
def search_start(token):
    global LocCounter
    global lineNum
    global errorNum

    progName = ''
    for i in range(len(token)):
        if token[i] == 'START': # 如果有找到 START，要 check 有沒有程式名稱 and 程式初始位置
            try:
                # 將以 16 進位表示的初始位置轉為 10 進位儲存，int() 可以將不同的值轉換為十進位制整數
                if int(token[len(token)-1], 16):
                    LocCounter = int(token[len(token)-1], 16)
                    if len(token) == 2 and token[0] == 'START': # 如果長度只有2 且 START 在第一個
                        errorNum += 1
                        print('Error, 缺少程式名稱, in line:', lineNum)
                        return LocCounter
                    else:
                        # 如果程式名稱 > 6 的話，報錯但繼續檢查
                        if len(token[0]) > 6:
                            outputPass1.append([str(lineNum), '***', token[2]])
                            errorNum += 1
                            print('Error, 程式名稱過長, in line:', lineNum)
                            return LocCounter
                        else: # 有程式名稱而且他 <= 6
                            # 若有找到合法 START，也有程式名稱，儲存程式名稱
                            progName = token[0]
                            outputPass1.append([str(lineNum), token[0], token[2]])
                            # print('Program name is '+ progName)
                            # print('start from this line')
                            # print()
                            return LocCounter
            except:
                print('Error, 程式起始位置不明(未定義或不符合 16 進位)無法繼續執行，程式中止, in line:', lineNum)
                os._exit(0)
            

def startOfProgram(token):
    global LocCounter
    global lineNum
    global opcode_table
    global errorNum

    if len(token) == 0:
        return # token 沒有東西就結束，換下一行
    else:
        if search_opCode(token[0]) == True: # 如果第一個是 mnemonic
            if token[0] == 'RSUB': 
                if len(token) == 1:
                    outputPass1.append([str(lineNum), hex(LocCounter), '***', token[0], '***', opcode_table.get(token[0]), '***',])
                    # print('Label: ', 'Mnemonic:', token[0], 'Oprand:')
                    LocCounter += 3
                else: # RSUB 後面不可以有 operand
                    errorNum += 1
                    print("Error, 格式錯誤, RSUB 後面不可接 operand, in line:", lineNum)
            else:
                if len(token) == 1:
                    errorNum += 1
                    print('Error, operand lost found, in line:', lineNum) # 因為可以單獨出現的 opcode 只有 RSUB 其他都需接上參數

                elif len(token) == 2: 
                    if token[1].find(',') == -1: # 如果在 operand 的位置找不到 ',' 就是 direct
                        outputPass1.append([str(lineNum), hex(LocCounter), '***', token[0], token[1], opcode_table.get(token[0]), 'direct'])
                    else: # indexed Addr: ['mnemonic', 'BUFFER,X']
                        if token[1].split(',', 1)[1] != 'X': # 先來檢查看看 indexed Addr 的格式有沒有對
                            errorNum += 1
                            print("Error, indexed Addressing 格式錯誤, in line:", lineNum)
                        else:
                            outputPass1.append([str(lineNum), hex(LocCounter), '***', token[0], token[1], opcode_table.get(token[0]), 'indexed'])
                
                elif len(token) > 2:
                    token[1] = ''.join(token[1:])
                    if token[1].find(',') == -1: # 原本在 operand 的地方有空格，又是 direct，就錯了，direct 的 operand 不能有空白
                        errorNum += 1
                        print("Error, instruction format error, in line:", lineNum)
                    else: # indexed Addr: ['mnemonic', 'BUFFER,X']
                        if token[1].split(',', 1)[1] != 'X': # 先來檢查看看 indexed Addr 的格式有沒有對
                            errorNum += 1
                            print("Error, indexed Addressing 格式錯誤, in line:", lineNum)
                        else:
                            outputPass1.append([str(lineNum), hex(LocCounter), '***', token[0], token[1], opcode_table.get(token[0]), 'indexed'])
                
                LocCounter += 3
        
        else: # 如果第一個不是 mnemonic
            if len(token) == 1:
                errorNum += 1
                print('Error, label 不能單獨出現, in line:', lineNum)
            elif len(token) == 2: # 如果 token[0] 不是 mnemonic，len() 又只有 2，只能夠是帶了 label 的 RSUB
                if token[1] == 'RSUB':
                    outputPass1.append([str(lineNum), hex(LocCounter), token[0], token[1], '***', opcode_table.get(token[1]), '***'])
                    # print('Label: ',token[0], 'Mnemonic:', token[1], 'Oprand:')
                    insert_symbolTab(token[0], LocCounter)
                    LocCounter += 3
                else: # 這個指令只有兩個 token，第一個不是 Mnemonic，第二個不是 RSUB。第二個有可能是 Mnemonic，也有可能還是
                    # label mnemonic -> operand lost found
                    # 非mnemonic mnemonic -> Error, 
                    if search_opCode(token[1]) == True: # 第二個是除了 RSUB 的 mnemonic
                        insert_symbolTab(token[0], LocCounter) # 還是要把這個 label 加進 symbol table
                        errorNum += 1
                        print('Error, operand lost found, in line:', lineNum) # 除了 RSUB 之外，其他 opcode 後面都要加 operand
                    else:
                        errorNum += 1
                        print('Mnemonic Error, 查無指令種類, in line:', lineNum) # 因為第二個不是 mnemonic，沒有這種指令格式

            else: # len(token) >= 3，要來檢查第二個是不是 mnemonic，如果也不是有定義的虛指令的話，就錯了
                if len(token) > 3:
                    token[2] = ''.join(token[2:])
                if search_opCode(token[1]) == True: # 第二個是 mnemonic，所以檢查後面 operand 的定址模式
                    print(token)
                    if token[0] == token[2]:
                        errorNum += 1
                        print("Error, label == operand, in line:", lineNum)
                    elif token[1] == 'RSUB': # 如果第二個是 RSUB 而且這個指令的長度還 > 2，就一定是錯啦，RSUB 不能有 operand
                        errorNum += 1
                        print("Error, RSUB 不能有 operand, in line:", lineNum)
                    # 要先來檢查是不是 direct addr
                    elif token[2].find(',') == -1 and token[1] != 'RSUB':
                        if len(token) == 3: 
                            outputPass1.append([str(lineNum), hex(LocCounter), token[0], token[1], token[2], opcode_table.get(token[1]), 'direct'])
                            # print('This is direct addressing!')
                            # print('Label: ', token[0], 'Mnemonic:', token[1], 'Oprand:', token[2])
                        else:
                            # build_symbolTab(token[0], LocCounter) # 還是要把這個 label 加進 symbol table
                            errorNum += 1
                            print("Error, instruction format error, in line:", lineNum)
                    else: # indexed
                        # token[2] = ''.join(token[2:])
                        if token[2].split(',', 1)[1] != 'X': # 去看看格式有沒有對(用逗號去切出兩格看看後面的字串是不是大寫 X)
                            errorNum += 1
                            print("Error, indexed Addressing 格式錯誤, in line:", lineNum)
                        else:
                            outputPass1.append([str(lineNum), hex(LocCounter), token[0], token[1], token[2], opcode_table.get(token[1]), 'indexed'])
                        # print('This is indexed addressing!')
                        # print('Label:', token[0], 'Mnemonic:', token[1], 'Oprand:', token[2])
                    insert_symbolTab(token[0], LocCounter)
                    LocCounter += 3
                # 以下是第二個是不是 mnemonic，所以來檢查是否為合法虛指令
                elif token[1] == 'RESW':
                    try:
                        token[2] == '0' or int(token[2])
                        outputPass1.append([str(lineNum), hex(LocCounter), token[0], token[1], token[2], '***', '***'])
                        insert_symbolTab(token[0], LocCounter)
                        LocCounter += int(token[2])*3
                    except:
                        errorNum += 1
                        print("Error, RESW 後面需接 10 進位, in line:", lineNum)
                    # print('RESW is persudo instruction code')
                elif token[1] == 'RESB':
                    try:
                        token[2] == '0' or int(token[2])
                        outputPass1.append([str(lineNum), hex(LocCounter), token[0], token[1], token[2], '***', '***'])
                        insert_symbolTab(token[0], LocCounter)
                        LocCounter += int(token[2])
                    except:
                        errorNum += 1
                        print("Error, RESB 後面需接 10 進位, in line:", lineNum)
                    # print('RESB is persudo instruction code')
                elif token[1] == 'WORD':
                    try: 
                        if token[2] == '0' or int(token[2]): # WORD 只能存 10 進位的數字 int() 這裡不知道為甚麼 int(0) 怪怪的
                            if int(token[2]) > int('1000000', 16): # 確定是十進位的數字之後再比較大小，不能超過 6 byte
                                insert_symbolTab(token[0], LocCounter) # 還是要把這個 label 嘉進 symbol table
                                errorNum += 1
                                print('Error, 超過 WORD 可儲存之範圍, in line:', lineNum)
                            else:
                                token[2] = hex(int(token[2]))
                                # 存進中間檔的數值已被轉乘 16 進位
                                outputPass1.append([str(lineNum), hex(LocCounter), token[0], token[1], token[2][2:], '***', '***'])
                                insert_symbolTab(token[0], LocCounter)
                                LocCounter += 3
                    except:
                        insert_symbolTab(token[0], LocCounter) # 還是要把這個 label 加進 symbol table
                        errorNum += 1
                        print("Error, 格式錯誤, WORD 後面需要接 10 進位的數字, in line:", lineNum)
                    
                elif token[1] == 'BYTE':
                    # print("BYTE is persudo instruction code")
                    insert_symbolTab(token[0], LocCounter)
                    item = "'"
                    if token[2].count(item) != 2: # check 單引號有沒有成對
                        errorNum += 1
                        print("Error, BYTE 指令格式錯誤，單引號是成對的, in line:", lineNum)
                    elif token[2].find(item, 2) != len(token[2])-1: # 如果單引號不是最後一個字元，代表後面還有其他咚咚，格式錯誤
                        errorNum += 1
                        print("Error, BYTE 指令格式錯誤, in line:", lineNum)
                    # 單引號是成對的，確認 BYTE 後面是 X 或 C，再來檢查內容有沒有空白，所以若為空白，長度會只等於3
                    elif "X" == token[2][0]:
                        if len(token[2]) == 3:
                            errorNum += 1
                            print("Error, contain of 'BYTE' is null, in line:", lineNum)
                        else:
                            try: # 如果是要存要存 16 進位，要檢查是否為合法 16 進位數字
                                tryTheNum = '0x'+ token[2][2:len(token[2])-1]
                                if len(token[2][2:len(token[2])-1]) % 2 == 0: # 先確認此數值長度是否為偶數
                                    if int(tryTheNum, 16): # 長度確認為偶數，再來確認此數值是否為 16 進位
                                        outputPass1.append([str(lineNum), hex(LocCounter), token[0], token[1], token[2][2:len(token[2])-1], '***', '***'])
                                        loc = (len(token[2]) - 3)/2
                                        LocCounter += int(loc)
                                else: # 此數值字串不是偶數
                                    errorNum += 1
                                    print("Error,  BYTE 的 X 型態內容要偶數長度, in line:", lineNum)
                            except:
                                errorNum += 1
                                print("Error, X 後面只能接 16 進位的數字 in line:", lineNum)
                        
                    elif "C" == token[2][0]:
                        if len(token[2]) == 3: # 檢查內容有沒有空白
                            errorNum += 1
                            print("Error, contain of 'BYTE' is null, in line:", lineNum)
                        else:
                            charToASCII = '' # 存轉成 16 進位的 ASCII 碼
                            charToStore = token[2][2:len(token[2])-1] # 提取出字元
                            for i in range(len(charToStore)):
                                ASCIItoHex = hex(ord(charToStore[i]))
                                charToASCII += ASCIItoHex[2:]
                            outputPass1.append([str(lineNum), hex(LocCounter), token[0], token[1], charToASCII, '***', '***'])
                            loc = len(token[2]) - 3
                            LocCounter += int(loc)
                    else: # BYTE 後面不是 C 也不是 X
                        errorNum += 1
                        print("Error, 指令格式錯誤， BYTE 後面出現了除了 X 或是 C 的表示法, in line:", lineNum)
                else: # 第二個不是 mnemonic，也不是已定義虛指令
                    errorNum += 1
                    print("Mnemonic Error, 查無指令種類, in line:", lineNum) # 因為第二個不是 mnemonic，沒有這種指令格式
    # print()

def passOneProg():
    global opcode_table
    global LocCounter
    global lineNum
    global errorNum

    alreadyEnd = False
    path = 'testSIC.txt'
    f = open(path, 'r')
    # 先一行一行掃
    for line in f.readlines():
        # 在分割前先 check 有沒有 . 把 . 之後的都刪掉
        if '.' in line: # 如果有註解在後面
            commentLoc = line.find('.') # 找到 . 的時候會回傳第一個出現的位置
            line = line[:commentLoc] # 把註解都刪掉
        # else:
        #     pass
        if "'" in line and 'C' in line: 
            token = line[:line.find("'")].split() # ' 之前的字串用切斷
            token[len(token) -1] += line[line.find("'"):len(line)-1] # 把 '' 裡的字串合併到 token 最後一個裡面
        else:
            token = line.split()# 利用空格來分出字串
        # print(lineNum, ':', LocCounter, line, end='')
        # lineNum += 1 
        if len(token) > 0 and alreadyEnd == True: # 如果 你是 END 後面的一行
            errorNum += 1
            print("Error, END 後面的指令無效, in line:", lineNum)
            break # 不合法的指令 後面的也都不用做了
        elif LocCounter != None: # 在這個 for 迴圈裡面我已經找到 START 了，程式已經開始了
            if len(token) >= 1 and token[0] == 'END': # 先 check 這句是不是 END，不是 END 的話就再進去跑
                # END 有結束位置的話(len(token) == 2)，去 check 這個結束位置有沒有在 symbol table(symbol_table.get(token[1], 0) != 0)
                if len(token) == 2: 
                    totalProg = LocCounter - initial
                    alreadyEnd = True
                    outputPass1.append([str(lineNum), hex(LocCounter), '***', token[0], token[1], '***', '***'])
                    outputPass1.append([hex(totalProg)])
                    # print("程式總長:", hex(totalProg))
                    # print("End of the program")
                    
                else: # 雖然有 END，但沒有END返回位置，累積報錯
                    errorNum += 1
                    print("Error, END 沒有返回位置, in line:", lineNum)
            else:
                startOfProgram(token)
        else: # 如果 LocCounter 都沒有被設定代表還沒找到 START
            # 如果不是空字串，又沒有 START 在裡面，代表還沒開始就有指令想執行
            if len(token) > 0 and "START" not in token:
                errorNum += 1
                print("Error, START 都還沒找到前指令不能執行!, in line:", lineNum)
            else: # 會進來的: 空字串、有 START 的指令
                initial = search_start(token)
        lineNum += 1
    if LocCounter == None: # 如果全部檔案都找完了，都還是沒有找到 START
        print('Error, 程式起始執行位置不明( 沒找到 START )無法繼續執行，程式中止')
        os._exit(0)
    elif alreadyEnd == False: # 如果找完全部了，還是沒有找到 END，就報錯
        errorNum += 1
        print("Error, 缺少 END")
    f.close()

def main():
    global opcode_table
    global LocCounter
    global lineNum
    global errorNum

    # 先建立 opcode table
    path = 'opCode.txt'
    f = open(path, 'r')
    for line in f.readlines():
        opCode = line.split()
        # table["KEY"] = VALUE
        opcode_table[opCode[0]] = opCode[1]
    f.close()

    passOneProg()
    
    intermediateFilePath = 'intermediate.txt'
    intermediateFile = open(intermediateFilePath, 'w')
    for i in range(len(outputPass1)):
        for j in range(len(outputPass1[i])):
            intermediateFile.write(outputPass1[i][j]+' ')
        intermediateFile.write('\n')
    intermediateFile.close()

    # PASS 1 結束，開始 PASS 2
    passTwoProg()
    # print("Error Number:", errorNum)
    # print('Symbol Table:', symbol_table)
main()
