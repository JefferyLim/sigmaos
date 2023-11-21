#!/bin/bash


# Pass in all the keys you would like to add 
eval $(ssh-agent -s)
ssh-add "$@"
ssh-add -l
