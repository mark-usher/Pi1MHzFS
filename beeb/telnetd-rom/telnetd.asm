\ telnetd.rom - run helper 20 (the telnet daemon) on every reset.
\
\ Helper 20 hooks the Beeb's keyboard and RS423 output to the Pi, and a BREAK
\ undoes the hooks.  This sideways ROM puts them back: the MOS offers every ROM
\ service call 1 on a reset, and this answers it with the equivalent of
\
\       X%=20 : CALL &FC88
\
\ so a telnet session survives BREAK and CTRL-BREAK with nothing to type.
\
\ It also lets the Pi ask what is on the screen, silently.  The Pi cannot read the
\ Beeb's screen and a program cannot be interrupted to read it, but the foreground
\ code that is waiting for a key calls the buffer-remove vector (REMV) over and over,
\ so this ROM takes that vector (as an extended vector, which pages this ROM in).  The
\ Pi puts one byte, &FF, in the keyboard buffer; REMV sees it come out, keeps it from
\ the program, reads every character cell of the screen (OSBYTE 135) and sends the ones
\ that are not blank to the Pi as VDU 31,x,y,char with the screen drivers switched off,
\ so nothing shows on the Beeb, and puts the cursor back.  It runs on the host, so it
\ works with a second processor on.  Nothing is kept in zero page, which the MOS's
\ OSBYTE and VDU routines use: only the stack.  No workspace, no commands, no language.
\
\ Put it in a ROM socket (an EPROM), or load it into sideways RAM like any other
\ ROM image.  On a BBC B press BREAK; on a Master 128 also *INSERT its bank, which
\ the MOS needs for a ROM that appeared after the last reset (*ROMS shows the bank).  The same image works on
\ a B, B+ and Master 128: plain 6502, and the only OS call is OSBYTE &FD.
\
\ POWER-ON.  The Pi is usually powered from the Beeb, so at power-on it is
\ booting while the Beeb runs its ROM scan, and its window at &FC88 does not
\ answer for about two seconds.  After a power-on reset (OSBYTE &FD, X=1) this
\ waits, up to about 6 seconds, for the window to answer before running the
\ helper; after any other reset the Pi is already up and it does not wait.  If
\ no Pi ever answers it gives up and the Beeb carries on booting.
\
\ Service call 1 is used, not 3, for the reason the 1MHz-WiFi ROM gives: a
\ filing system that claims 3 stops the call reaching a ROM below it, and 1 is
\ never claimed.  A, X and Y are given back as they came - the MOS keeps its
\ slot number in X, and a ROM that does not claim the call must not change Y.
\
\ Build: beeb/telnetd-rom/build.sh (needs beebasm).

OSBYTE = &FFF4
OSWRCH = &FFEE
CMDPTR = &F2                \ service call 4: the command line, and Y its offset
HELPER_ENTRY = &FC88        \ the helper window: STX &FC88 / NOP / JMP &FD00
HELPER_OPCODE = &8E         \ the Pi writes STX abs here, so it is there only if a Pi1MHz answers
TELNET_HELPER = 20
INSV = &022A                \ the MOS vectors: keyboard buffer insertion ...
IRQ1V = &0204               \ ... and the interrupt
REMV = &022C                \ buffer remove, vector 22: foreground code polls it while it waits for a key
EXTVEC = &0D9F              \ the extended vector table: 3 bytes per vector (address, ROM number)
REMV_ENTRY = &FF42          \ the MOS's entry for vector 22 as an extended vector (&FF00 + 3*22)
SCANKEY = &FF               \ the byte the Pi puts in the keyboard buffer to ask for the screen
STUBPAGE = &FC              \ the stub's page (FRED); only a test build, in RAM, changes it
POWER_ON = 1                \ OSBYTE &FD: 0 soft BREAK, 1 power-on, 2 CTRL-BREAK
WAIT_TURNS = 40             \ x about 0.16 s at 2 MHz: a little over 6 seconds

ORG &8000
GUARD &C000

.romstart       equb 0                      \ no language entry
                equb 0
                equb 0
                jmp service
                equb &82                    \ service ROM, no language
                equb (copyright - romstart) \ copyright offset
                equb 1                      \ binary version
.romtitle       equs "TelnetD"
                equb 0
.romversion     equs "0.1"
.copyright      equb 0
                equs "(C)2026 Pi1MHz"
                equb 0

\ A is the reason code, X this ROM's slot, Y the reason argument.  Anything but
\ reset is passed on with all three untouched.
.service        cmp #1
                bne done
                pha                         \ the MOS wants A, X and Y back
                txa
                pha
                tya
                pha
                lda #&FD                    \ how did this reset start?
                ldx #0
                ldy #&FF
                jsr OSBYTE                  \ X = 0, 1 or 2
                cpx #POWER_ON
                bne probe                   \ the Pi is already up
                lda #WAIT_TURNS
                pha                         \ turns left, on the stack: nothing else is ours
.wait           lda HELPER_ENTRY
                cmp #HELPER_OPCODE
                beq ready
                ldx #0                      \ about 0.16 s
                ldy #0
.spin           dey
                bne spin
                dex
                bne spin
                pla
                sec
                sbc #1
                pha
                bne wait
.ready          pla                         \ the turns left
.probe          lda HELPER_ENTRY            \ is there a Pi1MHz to answer?  It may have been
                cmp #HELPER_OPCODE          \ moved, or the card have no 6502code.bin: then
                bne nopi                    \ there is nothing to run
                jsr unstale
                ldx #TELNET_HELPER
                jsr HELPER_ENTRY            \ the helper hooks the vectors and sets *FX3,1
                tsx
                lda &102,x                  \ this ROM's slot, as the MOS gave it in X
                jsr claimremv               \ A = what to tell the Pi: &21 if it can ask for the screen
                jsr marker
.nopi           pla
                tay
                pla
                tax
                pla
.done           rts

\ A software BREAK (CALL !-4, the reset vector) can leave the interrupt vector pointing
\ at the stub the helper installed before it, which the helper takes for another
\ program's hook and gives up.  A stub is recognised by its first two bytes (CPX #2) and
\ the vector pointing 12 into it; it kept the vector it replaced at +0D, which goes back.
.unstale        lda IRQ1V+1
                cmp #&FC
                bne unsx
                lda IRQ1V
                sec
                sbc #&0C
                tax                         \ X = where the stub would start
                lda &FC00,x
                cmp #&E0
                bne unsx
                lda &FC01,x
                cmp #2
                bne unsx
                lda &FC0D,x
                sta IRQ1V
                lda &FC0E,x
                sta IRQ1V+1
.unsx           rts

\ Tell the Pi this was a reset: its reset line is not touched by a software BREAK.
\ The stub's control port is at +28, and INSV points at the stub once it is hooked in.
.marker         pha
                lda INSV+1
                cmp #&FC
                bne mkx
                ldy INSV
                pla
                sta &FC28,y
                rts
.mkx            pla
                rts

\ Claim REMV, as a ROM does: the vector points at the MOS's extended vector entry for
\ it, and the extended vector table says where in which ROM the routine is.  The MOS's
\ own routine is kept in the table slot of vector 0 (USERV), which a ROM never claims.
\ In: A = this ROM's slot.  Out: A = &21 if claimed, &20 if not (the vector is
\ somebody's extended vector already, or the MOS has no extended vectors).
.claimremv      ldx REMV+1
                cpx #&FF
                beq notours
                pha
                lda REMV
                sta EXTVEC
                lda REMV+1
                sta EXTVEC+1
                lda #<remvh
                sta EXTVEC+66
                lda #>remvh
                sta EXTVEC+67
                pla
                sta EXTVEC+68
                lda #<REMV_ENTRY
                sta REMV
                lda #>REMV_ENTRY
                sta REMV+1
                lda #&21
                rts
.notours        lda #&20
                rts

\ REMV: X = the buffer, V clear to remove a byte, set to look at it; on return Y is the byte
\ and C set if there is none.  The keyboard buffer (X=0) is read by whatever is waiting
\ for a key, so this is called over and over while the Beeb is idle at a prompt, outside any
\ interrupt.  A byte of SCANKEY is the Pi asking for the screen: it is not given to the
\ program, the screen is read and sent (nothing shown), and the buffer is reported empty.
.remvh          php
                cpx #0
                bne remvold
                bvs remvold
                plp
                jsr remvcall
                bcs remvret
                cpy #SCANKEY
                beq remvscan
                clc
.remvret        rts
.remvscan       pha
                txa
                pha
                jsr scan
                pla
                tax
                pla
                ldy #0
                sec
                rts
.remvold        plp
.remvcall       jmp (EXTVEC)

.coltab         equb 80, 40, 20, 80, 40, 20, 40, 40     \ text columns in MODE 0 to 7
.rowtab         equb 32, 32, 32, 25, 32, 32, 25, 25     \ ... and rows

\ Send the screen to the Pi.  The Pi gets the characters only, as VDU 31,x,y,char with
\ the VDU drivers off (OSBYTE 3, X=3); the Beeb's cursor is moved on the screen to read
\ each cell, and put back.  Nothing is kept in zero page, which the MOS's OSBYTE and VDU
\ routines use: the counters live on the stack, below the return address, from the top:
\   &101,x column  &102,x row  &103,x the output streams as they were
\   &104,x cursor column  &105,x cursor row  &106,x columns  &107,x rows
.scan           lda INSV+1                  \ the Pi is hooked in when the keyboard vector is its stub
                cmp #STUBPAGE
                beq scango
                rts
.scango         lda #135                    \ Y = the mode
                jsr OSBYTE
                tya
                and #7
                tax
                lda rowtab,x
                pha                         \ rows
                lda coltab,x
                pha                         \ columns
                lda #134                    \ the cursor, to put back
                jsr OSBYTE
                tya
                pha                         \ cursor row
                txa
                pha                         \ cursor column
                lda #3                      \ the screen only, and what it was
                ldx #0
                jsr OSBYTE
                txa
                pha                         \ the streams as they were
                lda #0
                pha                         \ row
                pha                         \ column
                jsr topi
                lda #12                     \ the Pi starts from a clear screen
                jsr OSWRCH
                jsr toscr
.scancol        tsx
                lda &101,x
                ldy &102,x
                jsr locate                  \ the cursor to the cell, on the screen
                lda #135
                jsr OSBYTE                  \ X = the character at the cursor
                txa
                beq scanskip                \ 0: not a character the MOS knows
                cmp #32
                beq scanskip
                pha
                jsr topi
                tsx
                lda &102,x                  \ column and row are one deeper with the character pushed
                ldy &103,x
                jsr locate
                pla
                jsr OSWRCH
                jsr toscr
.scanskip       tsx
                inc &101,x
                lda &101,x
                cmp &106,x
                bne scancol
                lda #0
                sta &101,x
                inc &102,x
                lda &102,x
                cmp &107,x
                bne scancol
                tsx                         \ the cursor back, on the screen and for the Pi
                lda &104,x
                ldy &105,x
                jsr locate
                jsr topi
                tsx
                lda &104,x
                ldy &105,x
                jsr locate
                tsx
                lda &103,x
                tax
                lda #3
                jsr OSBYTE                  \ the streams as they were
                pla
                pla
                pla
                pla
                pla
                pla
                pla
                rts

.locate         pha                         \ VDU 31,A,Y (OSWRCH keeps Y)
                lda #31
                jsr OSWRCH
                pla
                jsr OSWRCH
                tya
                jmp OSWRCH
.topi           lda #3                      \ output to RS423 only
                ldx #3
                jmp OSBYTE
.toscr          lda #3                      \ output to the screen only
                ldx #0
                jmp OSBYTE

.romend

SAVE "telnetd.rom", &8000, &C000
