# From https://github.com/michael-emmi/issta2018-benchmarks-wu

# Wu et al.’s ISSTA 2018 Benchmarks

This is a collection of the benchmarks used in Wu et al.’s ISSTA 2018 paper *Eliminating Timing Side-Channel Leaks using Program Repair*.

This repository does not contain the tool submitted with the artifact, although it does include the scripts used to run the tool. Below are the original instructions for ISSTA artifact evaluation.

## Artifact Evaluation Instructions

Simply run our all in one script:

       ./run.sh

It will automatically run all existing benchmarks, and collect results into result.cvs file in current directory.

Or, by putting a specific benchmark as parameter:

       ./run.sh appliedCryp/3way

(note: do not append file extension, only the name) It will only run one benchmark at one time.
