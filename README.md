Malicious
=========

ASM Malicious Code - Let's play a game

Create the most undetectable ASM virus that we can using http://www.virustotal.com (55 AntiVirus)

Capacities
* Reproduction by infecting near PE files
* Basic polymorphism
* Communication via 'HTTP'

We start by testing on a HelloWorld sample using g++.
An empty main with gcc will result into 5 flags. HelloWorld with gcc two flags. And only one with g++.
AegisLab seems to be giving too many false positives, we will not take him into accounts.

<br>
**Version #1**
* creating new section
* changing entry point (EP)
* infect \*.exe in current directory
* get back to old EP

`> We got 13 flags (out of 54!)`
> We note that we got only 1 flag if we don't change the EP so most of them only check the section pointed by the EP or use only a sandbox as detection method.


<br>
**Version #2**
* polymorphism (xoring by random value)

We still expect a lot of flags since it doesn't change our behaviour (in a sandbox)

`> We got 6 flags. Nice.`

That means only half of them use sandbox detection and the others cannot check our behavior via a crypted section (and was only checking the section pointed by EP).
> Strangely, all the flags are from unknown AVs (from the general public). Avast, Avira, AVG are all bypassed.

<br>
**Going deeper**

How can we become less detectable ? We need to know what cause the flags in our 6 AVs.
We should check :
* the entry point : jmping from one section to another should be suspicious
* behavior : since we infect all the .exe in the directory, sandbox detection system will detect it
* a better encryption method

> Why a better encryption ? We note that by reinfecting (to change the random xor value to encrypt) we 
> got different detection rate from 5 to 8 flags.

<br>
**Let's do some testing**

When we create a new section, empty with an exit, only changing the EP to our section will get us 3 flags
The action to change the EP to the last section will alert half of the one I have in version #2. I've got an idea.

Now for the last 3 (and probably the best one since they flag the actual threat and not some kind 
of characteristics in the format) which are DrWeb, NANO-Antivirus and TrendMicro probably flag the 
fact that I infect some binaries. It will be a lot harder to hide this. AV evasion maybe ?

<br>
**Version #3**
