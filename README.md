# assembler_SIC_twoPass
> SIC 版本的 two pass assembler
- pass1: 將 source code 轉成 op code，並將相關資訊存至 intermediate file
- pass2: 根據 intermediate file 裡面的內容組合出完整的 object program 或進行報錯
## 正常輸出
![image](https://github.com/hunglee13/assembler_SIC_twoPass/assets/105621295/32fcddbf-7822-4176-b758-1ccb4dad0c10)
## 基礎功能
1. 如果 source code 有錯，會顯示錯誤
2. START 可以更換起始位置
3. END operand 可以隨意更換位置
4. 重複定義的 symbol: duplicate definition
5. Undefined symbol
6. Mnemonic Error
7. 遇到 RESW, RESB 會換行
8. 可分辨 direct addressing 和 indexed addressing
## 防呆
1. RSUB 有 label
2. Indexed addressing 前後可以有空格
3. BYTE C   'EOF'，C 和單引號之間可以有空格
4. BYTE C'E  O      F'，單引號間可以有空格
5. BYTE C'EOFFFFFFFFFFFFF'，裡面可以無限字元
## 可顯示錯誤
1. START 開始之前有指令
2. START 不是 16 進位
3. END 後面還有指令
4. Instruction format error
5. Indexed Addressing 格式錯誤
6. WORD operand 不是十進位
7. BYTE 後面不是 C or X
8. BYTE 少了單引號
9. BYTE X 出現半個 byte
10. BYTE X 不是 16 進位
11. Contain of byte is null
12. RSUB 有 operand
13. Command 沒有 operand
14. Label == Operand
15. Label or Operand is mnemonic
