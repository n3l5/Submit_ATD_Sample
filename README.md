# Submit_ATD_Sample
Python script to submit files in a directory or a single file to an ATD server.

This isn't anything fancy, it just submits and gives you some smaple info; you won't get the status/results of your submission. 

To make this script work, you'll need to add some things:
1. atdUser - this is the ATD username w/ API rights
2. atdPwd - this is the password for the above atdUser
3. vmProfileIDNum - this is the profile ID you want these samples to run in. 

Note: It isn't a great idea to have static users/passwords in a script sitting around; you should use an ATD user that is local to the ATD server with no other rights to ATD (api only) and no other rights anywhere else.
