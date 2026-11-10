@ Reference runner for qemu-arm: calls test_fn(in, out) and write()s the result.
    .syntax unified
    .arm
    .global _start
_start:
    ldr r0, =state_in
    ldr r1, =state_out
    bl test_fn
    mov r0, #1
    ldr r1, =state_out
    ldr r2, =state_size
    ldr r2, [r2]
    mov r7, #4          @ write
    svc #0
    mov r0, #0
    mov r7, #1          @ exit
    svc #0
    .ltorg
