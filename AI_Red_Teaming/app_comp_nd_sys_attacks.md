---
layout: default
title: Attacking App Components
permalink: /AI/app_comp_nd_sys_attacks/
---

# Attacking Application or System Components

## Model Reverse Engineering
When an adversary attempts to reconstruct or approximate the deployed model. By systematically sending inputs to the model through an exposed API and observing the outputs, the adversary collects enough input-output data points to train a surrogate model that mimics the original model's behavior.

## Denial of ML Service
ML deployments may be vulnerable to common Denial-of-Service (DoS) attack vectors, such as flooding the system with network traffic to overwhelm its resources, they can also be targeted by DoS attacks that directly exploit the deployment components.
### Sponge Examples
Sponge Examples are specifically crafted adversarial inputs that maximize energy consumption and latency in the ML mode without increasing the input dimension, since limiting the input dimension can prevent DoS attacks resulting from overly high-dimensional inputs. For this task genetic algorithms can be used.

Two factor for text-based sponge examples impact a model's processing time, energy consumption and inference latency. The first factor is the output sequence length, the second factor is the number of input tokens.

### Mitigations
Traditional DoS mitigations can help, but we need further mitigations, e.g. uery monitoring, robust model design, introduce a cutoff threshold for maximum energy consumption or inference time, etc.

## Insecure Integrated Components
Real-world ML applications often comprise a vast array of interacting components. If any of these suffer from security vulnerabilities, it poses a risk to the ML application.
