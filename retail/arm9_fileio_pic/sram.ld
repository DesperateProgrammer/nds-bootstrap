MEMORY
{
    ram : ORIGIN = 0x02000000, LENGTH = 1K
}

SECTIONS
{
    .text 0x02000000 : 
    { 
      *(.text) 
    } 
}