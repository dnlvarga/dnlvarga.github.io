---
layout: default
title: Attacking the data
permalink: /AI/data_attacks/
---

# Attacking Data Components

Improper training data is a significant risk. This can include biased or unrepresentative training data.

## Data Poisoning
The goal is to degrade a model’s overall accuracy or coerce specific misclassifications.

### Label Flipping
If an adversary gains access to a portian of the training dataset and changes the assgined labels (the correct answers or categories) for some data points. The actual features of the data points remain untouched

### Targeted Label Attacks
Instead of just reducing overall accuracy, Targeted Label Attack has a more specific objective: to cause the trained model to misclassify specific, chosen target instances or instances belonging to a particular target class. 

### Clean Label Attacks
This is a feature attack and another category of data poisoning attacks. This attack does not alter the ground truth labels of the training data. Instead, it carefully modifies the features of one or more training instances. These modifications are crafted such that the original assigned label remains plausible (or technically correct) for the modified features. The goal is typically highly targeted: to cause the model trained on this poisoned data to misclassify specific instances.

## Trojan Attacks or Backdoor Attacks
This attack hides malicious logic inside an otherwise fully functional model. The logic remains dormant until a particular trigger appears in the input.

## Tensor Steganography
The practice of hiding information within the numerical parameters of a neural network model is known as Tensor Steganography. This technique leverages the fact that models contain millions, sometimes billions or even trillions, of parameters, typically represented as floating-point numbers.

pickle is Python's standard way to serialize an object (convert it into a byte stream) and deserialize it (reconstruct the object from the byte stream). While powerful, deserializing data from an untrusted source with pickle is dangerous. pickle allows objects to define a special method: __reduce__. When pickle.load() encounters an object with this method, it calls __reduce__ to get instructions on how to rebuild the object, and these instructions typically involve a callable (like a class constructor or a function) and its arguments. This can be exploited by creating a custom class where __reduce__ returns a dangerous callable, such as the built-in exec function or os.system, along with malicious arguments (like a string of code to execute or a system command).

## Steal Data
Gaining insight into the data set, adversaries can craft specific inputs to manipulate the model's outputs or exploit its vulnerabilities.
