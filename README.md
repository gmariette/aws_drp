# aws_drp
Test your infrastructure with this drp script

# Usage
Change from the DRP class the aws_account you want to reach.
The first level key in my case is an environment. It is use for example to lookup the desired ASG (line 527) or the DB instances (line 447 - describeRDSinstances Func)
You must specify the account id, the iam role and the region.
