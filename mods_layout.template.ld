ENTRY(main)

MEMORY
{
  APP (rwx) : ORIGIN = @APP@, LENGTH = 0x6000
  BSS (rwx) : ORIGIN = @BSS@, LENGTH = 0xffffff
}

SECTIONS
{

    .text :
    {
        *(.text)
        *(.text.*)
        *(.rodata)
        *(.rodata*)
    } > APP

    .data :
    {
        KEEP(*(.data))
        *(.data.*)
    } > APP

    .bss :
    {
        *(.bss)
        *(.bss.*)
    } > BSS

    DISCARD :
    {
        libc.a ( * )
        libm.a ( * )
        libgcc.a ( * )
        *(.eh_frame)
    }
}

/* vim:filetype=ld */
