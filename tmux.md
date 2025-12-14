---
layout: default
title: Tmux
permalink: /tmux/
---

You can use this [cheat sheat](https://tmuxcheatsheet.com/)

# copy-pasting

- Use vi mode: Prefix + `:` + `setw -g mode-keys vi`
- Then read mode: Prefix + `[`
- Navigate to the beginning of the text you want to copy. Page up on Mac is Command + Up arrow.
- Press Space and go to the end of the text you want to copy.
- Press Enter to put text into tmux clipboard and automatically exits read mode.
- Paste with Prefix + `]`

# Find&Replace

- to replace 'foo' with 'bar': `:%s/foo/bar/g`
