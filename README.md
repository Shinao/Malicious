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
> We note that we got only 1 flag if we don't change the EP (They almost all use behavioral detection)


<br>
**Version #2**
* polymorphism (xoring by random value)

We still expect a lot of flags since it doesn't change our behaviour (in a sandbox)

`> We got 6 flags. Nice.`

That means only half of them use sandbox detection and the others cannot check our behavior via a crypted section.
> Strangely, all the flags are from unknown AVs to me. Avast, Avira, AVG are all bypassed.

<br>
**Going deeper**

How to become FUD ? We need to know what cause the flags in our 6 AVs.
We should check :
* the entry point (Maybe it's just too unusual to have an EP pointing at the last section)
* behavior : since we infect all the .exe in the directory, in a sandbox it's an easy check
* a better encryption method

> We note that by reinfecting (to change the random xor value to encrypt) we 
> got different detection rate from 5 to 8 flags. Obviously the same amount of flags are triggered 
> when using the same xoring value.

<br>
