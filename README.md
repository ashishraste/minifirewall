<h1> minifirewall: a packet filtering firewall for Linux </h1>
minifirewall is a simple packet filtering firewall for Linux written in C. It uses Netfilter's hooks to watch the inbound
and outbound packets for a machine in a network.

<h2> Source files' description </h2>
Under the LKM directory: <br/>
``minifw.c`` : A Linux Kernel module (LKM) which implements Netfilter's hooks mainly ``NF_INET_LOCAL_IN`` and 
``NF_INET_LOCAL_OUT`` to filter the packets. <br/>
``minifw.h`` : Has all the structure details and other macros needed to implement the rules of minifirewall (the details 
in this header file must be consistent with the details in the user space minifirewall header).
<br/>
<br/>
Under the Userspace directory: <br/>
``minifirewall.c`` : This tool acts as the user space program for setting minifirewall's packet filtering rules. It uses 
"getopt.h" header to parse the arguments sent to it. Please get used to its arguments' notation. Will include the "help" 
details to the code after some clean-up work. <br/>
``minifirewall.h`` : Contains macros and structs as in minifw.c. All the fields in the struct my_ipt are initialised in 
minifirewall.c and are sent to minifw LKM through /proc. </br/> <br/>

<h2> Demo of minifirewall </h2>
Follow the steps given below to insert minifw LKM into the kernel.

        cd LKM
        make
        sudo insmod minifw.ko
        
You must see a module by the name ``minifw`` when you do a ``lsmod | head -3`` to list out the modules in your system.
Also you must observe that there is an entry by the name ``minifw`` in  the /proc directory which you can find out by doing a 
``ls /proc | grep "minifw"``.
<br/> <br/>
Run the user-space ``minifirewall`` program after compiling it. Follow the steps given below to test it.
        
        gcc -o -Wall minifirewall minifirewall.c
        sudo ./minifirewall --in --proto ALL --action BLOCK
        ping www.google.com

What do you observe? You should NOT be able to ping any server since you have written a minifirewall rule to block all
the incoming packets bounded to your system. Also you can try opening a webpage in your browser which should be 
unsuccessful. If not, then there is some problem with the passing/registering the rules with minifw.
<br/><br/>
Play around with some more rules of minifirewall by going through its source until I update a "help" section which
lists out all the parameters for minifirewall's rules. <br/> <br/>
Good luck!


        



