# Description

The code implement Security Anonymous Vote Environment. The example usage is show in the main part. It need one-to-one mapping function, colletion resist hash function, and secure random function; therefore, import the pycrypodome for using AES-ECB, SHA256, random to fulfill the requirement.

# Explanation

The environment setup four main characters that need not to share thier secret to each other.

Four main characters:
 * mask maker
 * vote revealer
 * mask dispatcher
 * vote collector

Use two secret one-to-one mapping function (such as the two AES function with two different key in example code) to swap the identities of voters. Mask maker and vote revealer hold one, and mask dispatcher and vote collector hold the other. It can prevent everyone, even the main characters, know what somebody vote.

The hash function is to prevent mask maker to reveal wrong mask list after the vote revealer reveal all the votes in anonymous. To prevent the sum up error in vote counting, everyone who know the revealed votes and mask can sum up by themselves.

# Dependency

show in requirement.txt.
