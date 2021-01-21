LFI-tool

LFI-tool is a simple LFI scanner,which can be used during CTFs and real world applications.It is a simple tool which may not work on urls where the input is properly sanitized or encoded properly.


Usage


It is relatively simple to use

`python3 LFI-tool.py -h`

the program  may takes the following arguments in input

-u : URL of the site eg: http://example.com/inedx.php?PARAM=
--tf: Specify a traversal file,by default it's set to "/etc/passwd"
--filter: Specify the error string that commonly occur during invalid param
--cfl: Specify a custom list for LFI
--r:  specify the file to read through the LFI,must speicfy and absolute path
--param-fuzz: use the option with 1 to fuzz the parameters

Disclaimer

I am not responsible for any kind of illegal acts you cause. This is meant to be used for ethical purposes by penetration testers.