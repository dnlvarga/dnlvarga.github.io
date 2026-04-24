---
layout: default
title: Attacking the model
permalink: /AI/model_attacks/
---

# Manipulating the input

## Rephrasing
Consider the words or phrases you choose to achieve your goal. Maybe you can social engineer a different scenario, etc.

## Overpowering
Overpower the malicious prompt/message with benign words to push the model toward classifing your input the way you want. You can achieve this by simply appending words to your input. This technique is particularly effective in cases where we can conceal the appended message from the victim.

# Manipulating the training data

We can force a classifier to misclassify a particular input by manipulating the training data set.

# Attacking Model Components

## Evasion attacks

Use carefully crafted malicious inputs to trick the model into deviating from its intended behavior.
One common type of evasion attack on LLMs is a Jailbreak, which aims to bypass restrictions imposed on LLMs.

A comprehensive guide with examples can be found [here](https://www.promptfoo.dev/blog/how-to-jailbreak-llms/).

## Model Theft
A model is the intellectual property (IP) of the party that trained the model.
Furthermore stealing a model provides an opportunity to experiment with strategic queries.


