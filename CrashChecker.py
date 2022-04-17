import subprocess


class CrashChecker(object):
    mock = """
    Classification: PROBABLY_NOT_EXPLOITABLE
Hash: 17daee0bb21623d8b6d382e07d0ae466.17daee0bb21623d8b6d382e07d0ae466
Command: libgif-fuzzing/main libgif-fuzzing/outputs/fuzz-master/crashes/id:000007,sig:06,src:000229+000182,op:splice,rep:2 libgif-fuzzing/outputs/fuzz-master/crashes/id:000007,sig:06,src:000229+000182,op:splice,rep:2
Faulting Frame:
   GifTranscoder::resizeBoxFilter @ 0x0000555555614720: in /root/libgif-fuzzing/main
Disassembly:
   0x0000555555614705: call 0x55555561be70 <__afl_maybe_log>
   0x000055555561470a: mov rax,QWORD PTR [rsp+0x10]
   0x000055555561470f: mov rcx,QWORD PTR [rsp+0x8]
   0x0000555555614714: mov rdx,QWORD PTR [rsp]
   0x0000555555614718: lea rsp,[rsp+0x98]
=> 0x0000555555614720: movzx edi,BYTE PTR [rsi]
   0x0000555555614723: inc rsi
   0x0000555555614726: mov rdx,QWORD PTR [rsp+0x108]
   0x000055555561472e: call 0x55555558ee80 <DGifExtensionToGCB@plt>
   0x0000555555614733: test eax,eax
Stack Head (3 entries):
   GifTranscoder::resizeBoxF @ 0x0000555555614720: in /root/libgif-fuzzing/main
   GifTranscoder::transcode  @ 0x000055555561377f: in /root/libgif-fuzzing/main
   main                      @ 0x000055555561cae5: in /root/libgif-fuzzing/main
Registers:
rax=0x0000000000000000 rbx=0x00000ffffffffd10 rcx=0x0000000000000003 rdx=0x0000000000000000
rsi=0x0000000000000000 rdi=0x00007fffffffe880 rbp=0x00007fffffffe910 rsp=0x00007fffffffe5e0
 r8=0x000061600000fd60  r9=0x00007fffffffe58f r10=0x00007fffffffe3a0 r11=0x00007ffff76c9490
r12=0x00000ffffffffcf4 r13=0x000060c00000bf80 r14=0x00000ffffffffd0e r15=0x00007fffffffe7a0
rip=0x0000555555614720 efl=0x0000000000010246  cs=0x0000000000000033  ss=0x000000000000002b
 ds=0x0000000000000000  es=0x0000000000000000  fs=0x0000000000000000  gs=0x0000000000000000
Extra Data:
   Description: Access violation near NULL on source operand
   Short description: SourceAvNearNull (16/22)
   Explanation: The target crashed on an access violation at an address matching the source operand of the current instruction. This likely indicates a read access violation, which may mean the application crashed on a simple NULL dereference to data structure that has no immediate effect on control of the processor.
---END SUMMARY---
Classification: PROBABLY_NOT_EXPLOITABLE
Hash: 59a62e589f32e790214ab0aec33954a9.59a62e589f32e790214ab0aec33954a9
Command: libgif-fuzzing/main libgif-fuzzing/outputs/fuzz-master/crashes/id:000016,sig:06,src:000294+000366,op:splice,rep:2 libgif-fuzzing/outputs/fuzz-master/crashes/id:000016,sig:06,src:000294+000366,op:splice,rep:2
Faulting Frame:
   GifTranscoder::resizeBoxFilter @ 0x0000555555614d68: in /root/libgif-fuzzing/main
Disassembly:
   0x0000555555614d4d: call 0x55555561be70 <__afl_maybe_log>
   0x0000555555614d52: mov rax,QWORD PTR [rsp+0x10]
   0x0000555555614d57: mov rcx,QWORD PTR [rsp+0x8]
   0x0000555555614d5c: mov rdx,QWORD PTR [rsp]
   0x0000555555614d60: lea rsp,[rsp+0x98]
=> 0x0000555555614d68: movzx esi,BYTE PTR [rdx]
   0x0000555555614d6b: inc rdx
   0x0000555555614d6e: mov r14,rdi
   0x0000555555614d71: call 0x55555558ec90 <EGifPutExtensionBlock@plt>
   0x0000555555614d76: nop WORD PTR cs:[rax+rax*1+0x0]
Stack Head (3 entries):
   GifTranscoder::resizeBoxF @ 0x0000555555614d68: in /root/libgif-fuzzing/main
   GifTranscoder::transcode  @ 0x000055555561377f: in /root/libgif-fuzzing/main
   main                      @ 0x000055555561cae5: in /root/libgif-fuzzing/main
Registers:
rax=0x0000000000000000 rbx=0x00007fffffffe820 rcx=0x0000000000000021 rdx=0x0000000000000000
rsi=0x00007fffffffe500 rdi=0x000060c00000bec0 rbp=0x00007fffffffe910 rsp=0x00007fffffffe5e0
 r8=0x000061600000fa60  r9=0x00007fffffffe5c0 r10=0x0000000000000000 r11=0x0000000000000000
r12=0x00000ffffffffd10 r13=0x000060c00000bf80 r14=0x000060c00000bec0 r15=0x00007fffffffe880
rip=0x0000555555614d68 efl=0x0000000000010246  cs=0x0000000000000033  ss=0x000000000000002b
 ds=0x0000000000000000  es=0x0000000000000000  fs=0x0000000000000000  gs=0x0000000000000000
Extra Data:
   Description: Access violation near NULL on source operand
   Short description: SourceAvNearNull (16/22)
   Explanation: The target crashed on an access violation at an address matching the source operand of the current instruction. This likely indicates a read access violation, which may mean the application crashed on a simple NULL dereference to data structure that has no immediate effect on control of the processor.
---END SUMMARY---
    """

    cwd = '.'
    cmd_exploitable = "/root/crashwalk/bin/cwdump /root/crashwalk.db | sed -n -e '/Classification: EXPLOITABLE/," \
                      "/END SUMMARY/ p' "
    cmd_probably = "/root/crashwalk/bin/cwdump /root/crashwalk.db | sed -n -e '/Classification: PROBABLY NOT " \
                   "EXPLOITABLE/,/END SUMMARY/ p' "

    def __init__(self, cwd='.'):
        self.cwd = cwd

    def check(self, mock=True):
        if mock:
            return self.mock
        result = subprocess.run(self.cmd_probably, shell=True, stdout=subprocess.PIPE)
        str_result = result.stdout.decode('utf-8')
        return str_result
