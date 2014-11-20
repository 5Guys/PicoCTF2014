#Baleful

The solution relies on Intel Pin, which is a binary instrumentation tool. Specifically, Pin provides the framework on which many tools are built. For Baleful, we use a tool that is already included, *inscount 0*. All this tool does is count the number of executions that the binary goes through. For Baleful, we use a method of brute-force to guess the password.

First, we have to unpack our binary. By examining the strings of the Binary, we notice that the binary was packed with the UPX packer. So, we simply unpack using the same packer.

The first actual step is to find the length of the password. I kind of assumed that the first thing the program would do would check the length of the password (all of the other problems did). So, I created a simple shell script that passed in *x* number of characters into the unpacked baleful binary -- referred to as uBale. By noting the differences in steps of execution, we can identify the correct length of the password (the password of correct length will have more executions than the password with incorrect length).

Now we can do a simple brute-force, again using Pin to reduce run-time drastically. We use another shell script to automate the process for guessing characters one at a time. uBale matches each character, and if it fails, terminates the match. So, by guessing each character (iterate through ASCII) table, we can guess each character, one at a time. Note: each password should still be 30 characters, so its padded with underscores to be 30 characters.

#Will add files later