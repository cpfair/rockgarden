.section ".text"

.global _entry
_entry:

.type jump_to_pbl_function__proxy function
jump_to_pbl_function__proxy:
    @ at this point, r1 contains the syscall index and r0 the jump table base
    @ So, we want to see if r1 is what we wish to proxy
@PROXY_SWITCH_BODY@
    @ This is the balance of the original jump_to_pbl_function after we patch in the jump to this proxy
    add r0, r0, r1
    ldr r2, [r0, #0]
    mov ip, r2
    pop {r0, r1, r2, r3}
    bx  ip

@PROXY_FCNS_BODY@
