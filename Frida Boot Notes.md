Taken from link: [YouTube](https://www.youtube.com/live/CLpW1tZCblo?si=ravOgcdTtHXDF2Ie)

### Loading another shared object/library to be used in a program (ELF)
Used to override a function from that shared object.
```
LD_PRELOAD
```

### Quickly see what shared library a binary uses (ELF)
```
ldd [binary]
```

### Create a 'proxy' to a shared object
`dlsym` function: obtains address of a symbol in a shared object/executable.
using the `#include <dlfcn.h>` header.

**Example:**
```
original_sleep = dlsym(RTLD_NEXT, "sleep");
```
RTLD_NEXT = search for sleep in the next shared library.

**dlsym requires you to use the dynamic linker**
On compilation:
```
gcc -fPIC -shared file.c -o file.so -ldl
```
`ldl` = use dynamic linker. Has to be at the end of the line
## Frida
### Spawn Frida with the program
```
frida ./[file]
```

### Attach Frida to the program
```
frida [file]
```

### Attach using PID
```
frida -p [pid]
OR
frida -p $(pidof [file])
```

### Frida commands
#### Get proc id
```
Process.id();
```

#### Get modules/libraries
```
Process.enumerateModulesSync();
```

#### Get exports from modules
```
Process.getModuleByName().enumerateExports();
```

**With debug symbols**
```
DebugSymbol.getFuntionByName("[export]");
```

**Without debug symbols**
```
Module.getExportByName([library/module], "[export]");
```
^ if the export name is unique, [library/module] can be substituted with `null`
This will return the address of the export
#### Load scripts with Frida
```
frida [file] -l [script].js
```

#### Intercept
```
Interceptor.attach([[target], [callbacks]);
```
**Target: memory address**
See section: Get exports from modules to find target memory address.

**Tip: use vars instead of addresses**
You can do something like this in a js script to make it look prettier.
```
var myfunc = DebugSymbol.getFunctionByName("myfunc");

Interceptor.attach(myfunc, [callbacks]);
```

**Callbacks**
You can specify what to do on function enter/exit with callbacks.
```
Interceptor.attach([target], {
	onEnter: function(args) {
		console.log("Hi");
	}
	onLeave: function(args) {
		console.log("Bye");
	}
});
```
`onEnter` allows you to access the args passed to the function.
`onLeave` allows you to access the return value of the function.
	*Note that omitting onLeave when it's not necessary helps with performance.*
You can use these to spy on these values (they may return as hex values)
	For this, you can us the js parseInt() for ints
Example:
```
console.log(parseInt(args[0]));
```
To print out the first argument

##### Overriding arguments
You can modify arguments for a function.

**Integers**
```
args[0] = ptr("0x01");
```
^ To change the value of the first argument to 1.

**Strings**
Allocate character array with `Memory.allocUtf8String` and get the pointer
```
var printf = DebugSymbol.getFunctionByName("printf");
var buf = Memory.allocUtf8String("Hello!");

Interceptor.attach(printf, {
	onEnter:function(args) {
		args[0] = buf;}
})
```
^ printf() being used as an target example here

##### Overriding return values
```
onLeave: function(retval);
```

**Example**
```
var randrange = DebugSymbol.getFunctionByName("rand_range");

Interceptor.attach(randrange, {
	onLeave: function(retval) {
		console.log(retval);  // print out return value
		retval.replace(prt("0x01")); // replace retval with 1
	}
});
```
^ rand_range being used as an example to always make it return 1